"""ChatOps dialog handling for @secbot comments."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import select

from aegis.db import get_session
from aegis.db.models import DialogTurn, Feedback, RepoPolicy, Repository
from aegis.llm.base import LLMError
from aegis.llm.router import LLMRouter
from aegis.obs import get_logger, metrics
from aegis.providers import get_provider
from aegis.repos import resolve
from aegis.schemas import DiscussionThread, EventKind, WebhookEvent

log = get_logger("aegis.dialog")

_MENTION = re.compile(r"(?i)(?:^|\s)@(?:secbot|aegis)\b")
_FP = re.compile(r"(?i)\b(false positive|fp)\b")
_IGNORE = re.compile(r"(?i)\bignore\b\s*,?\s*(`?[^`\s]+`?)?")
_SCAN_FULL = re.compile(r"(?i)\bscan\s+full\b")
_WHY = re.compile(r"(?i)\b(why|explain|how)\b")
_FINGERPRINT = re.compile(r"Finding fingerprint:\s*`([0-9a-f]{40})`")
_SCAN_ID = re.compile(r"Scan ID:\s*`([^`]+)`")


@dataclass(frozen=True, slots=True)
class DialogCommand:
    kind: str
    argument: str = ""


async def handle_dialog_event(event_json: str) -> None:
    ev = WebhookEvent.model_validate_json(event_json)
    if ev.kind is not EventKind.COMMENT:
        return
    body = ev.comment_body or ""
    if not should_answer(body, ev):
        log.info("dialog.ignored", provider=ev.provider.value, repo=ev.repo_slug, pr=ev.pr_id)
        return

    command = parse_command(body)
    ctx = await resolve(ev.provider, ev.repo_external_id, ev.repo_slug)
    if not ctx.access_token:
        log.warning("dialog.no_token", repo=ev.repo_slug, pr=ev.pr_id)
        return

    provider = get_provider(ev.provider)
    pr = await provider.fetch_pull_request(ev, ctx.access_token)
    thread = await provider.get_thread(pr, ctx.access_token, ev.thread_id or ev.comment_id or "")
    answer = await answer_command(ev, thread, command)
    ref = await provider.reply_in_thread(pr, ctx.access_token, thread.thread_id, answer)
    await _persist_turn(ev, thread, command, answer)
    metrics.dialog_turns_total.inc()
    log.info("dialog.answered", repo=ev.repo_slug, pr=ev.pr_id, ref=ref, command=command.kind)


def should_answer(body: str, ev: WebhookEvent) -> bool:
    if not body.strip():
        return False
    if _MENTION.search(body):
        return True
    return bool(ev.in_reply_to_id or ev.thread_id)


def parse_command(body: str) -> DialogCommand:
    cleaned = _MENTION.sub("", body).strip()
    if _FP.search(cleaned):
        return DialogCommand("false_positive", cleaned)
    if _SCAN_FULL.search(cleaned):
        return DialogCommand("scan_full", cleaned)
    m = _IGNORE.search(cleaned)
    if m:
        arg = (m.group(1) or "").strip("` ")
        return DialogCommand("ignore", arg)
    if _WHY.search(cleaned):
        return DialogCommand("explain", cleaned)
    return DialogCommand("explain", cleaned)


async def answer_command(
    ev: WebhookEvent,
    thread: DiscussionThread,
    command: DialogCommand,
) -> str:
    if command.kind == "false_positive":
        fp = _fingerprint(thread)
        await _record_feedback(ev, fp, "false_positive")
        return (
            "Marked this finding as a false positive for review. "
            "After repeated confirmations of the same fingerprint, Aegis suppresses it "
            "for future scans in this repository."
        )
    if command.kind == "ignore":
        await _add_ignore_glob(ev, command.argument)
        return f"Added repository ignore pattern: `{command.argument}`."
    if command.kind == "scan_full":
        return (
            "Retro-scan request received. The backend command is recognized; full repository "
            "scanner execution is handled by the retro module when enabled for this repo."
        )
    return await _explain_with_llm_or_fallback(thread, command)


async def _explain_with_llm_or_fallback(
    thread: DiscussionThread, command: DialogCommand
) -> str:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"answer": {"type": "string"}},
        "required": ["answer"],
    }
    messages = [
        {
            "role": "system",
            "content": (
                "You are Aegis, a defensive security reviewer. Explain the existing "
                "finding in the PR thread using only the supplied thread context. "
                "Be concrete and concise; include a safe fix direction."
            ),
        },
        {
            "role": "user",
            "content": f"Question: {command.argument}\n\nThread:\n{_thread_text(thread)}",
        },
    ]
    try:
        out = await LLMRouter().complete(
            role="detector_b", messages=messages, schema=schema, max_tokens=1200
        )
        answer = _extract_answer(out.content)
        if answer:
            return answer
    except LLMError as exc:
        log.warning("dialog.llm_failed", error=str(exc))
    return (
        "This thread is tied to an Aegis finding. The issue is considered security-relevant "
        "because the changed line is reachable from untrusted input or affects a sensitive "
        "operation. Apply the suggested fix, then push an update so Aegis can re-scan."
    )


async def _persist_turn(
    ev: WebhookEvent,
    thread: DiscussionThread,
    command: DialogCommand,
    answer: str,
) -> None:
    async with get_session() as session:
        existing = (
            await session.execute(
                select(DialogTurn).where(DialogTurn.thread_id == thread.thread_id)
            )
        ).scalars().all()
        session.add(
            DialogTurn(
                provider=ev.provider.value,
                repo_slug=ev.repo_slug,
                pr_id=ev.pr_id,
                thread_id=thread.thread_id,
                finding_fingerprint=_fingerprint(thread),
                turn=len(existing) + 1,
                author=ev.actor,
                question=command.argument or ev.comment_body or "",
                answer=answer,
            )
        )


async def _record_feedback(ev: WebhookEvent, fingerprint: str | None, kind: str) -> None:
    if not fingerprint:
        return
    async with get_session() as session:
        session.add(
            Feedback(
                scan_id=_scan_id_from_body(ev.comment_body or "") or f"dialog:{ev.delivery_id}",
                finding_fingerprint=fingerprint,
                kind=kind,
                author=ev.actor,
            )
        )
    metrics.fp_feedback_total.labels(kind).inc()


async def _add_ignore_glob(ev: WebhookEvent, pattern: str) -> None:
    if not pattern:
        return
    async with get_session() as session:
        repo = (
            await session.execute(
                select(Repository).where(
                    Repository.provider == ev.provider.value,
                    Repository.external_id == ev.repo_external_id,
                )
            )
        ).scalar_one_or_none()
        if repo is None:
            return
        policy = repo.policy
        if policy is None:
            policy = RepoPolicy(repo_id=repo.id)
            session.add(policy)
        current = list(policy.ignore_globs or [])
        if pattern not in current:
            current.append(pattern)
            policy.ignore_globs = current


def _fingerprint(thread: DiscussionThread) -> str | None:
    for comment in thread.comments:
        body = str(comment.get("body") or comment.get("content", {}).get("raw") or "")
        m = _FINGERPRINT.search(body)
        if m:
            return m.group(1)
    return None


def _scan_id_from_body(body: str) -> str | None:
    m = _SCAN_ID.search(body)
    return m.group(1) if m else None


def _thread_text(thread: DiscussionThread) -> str:
    parts: list[str] = []
    for comment in thread.comments[-8:]:
        author = comment.get("author") or comment.get("user", {}).get("login") or "unknown"
        body = comment.get("body") or comment.get("content", {}).get("raw") or ""
        parts.append(f"{author}: {body}")
    return "\n\n".join(parts)


def _extract_answer(content: str) -> str:
    import json

    text = content.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text if text and not text.startswith("{") else ""
    answer = data.get("answer") if isinstance(data, dict) else None
    return str(answer).strip() if answer else ""
