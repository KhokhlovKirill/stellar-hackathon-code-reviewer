"""@secbot command parser and executor for PR comment ChatOps."""

from __future__ import annotations

import re
from typing import Any

from aegis.observability.logging import get_logger

log = get_logger(__name__)

# Supported commands
COMMANDS = {
    "help": "Show available commands",
    "rescan": "Trigger a new security scan",
    "ignore": "Ignore a finding (provide finding ID or file:line)",
    "status": "Show current scan status",
    "findings": "List all findings for this PR",
    "fp": "Mark a finding as false positive",
    "approve": "Approve the PR (security team only)",
    "reject": "Reject the PR (security team only)",
    "retroscan": "Trigger retro scan on repository",
    "summary": "Show risk summary",
}

# Pattern: @secbot <command> [args]
_COMMAND_RE = re.compile(
    r"@secbot\s+(/?)(?P<cmd>\w+)(?:\s+(?P<args>.*))?",
    re.IGNORECASE,
)


def parse_command(message: str) -> tuple[str, dict[str, Any]]:
    """Parse a @secbot command from a PR comment.

    Returns:
        (command_name, args_dict)
    """
    match = _COMMAND_RE.search(message)
    if not match:
        return "unknown", {}

    cmd = match.group("cmd").lower()
    raw_args = (match.group("args") or "").strip()

    if cmd not in COMMANDS:
        return "unknown", {"raw": raw_args, "attempted_cmd": cmd}

    args = _parse_args(cmd, raw_args)
    return cmd, args


def _parse_args(cmd: str, raw_args: str) -> dict[str, Any]:
    """Parse command-specific arguments."""
    if cmd in ("ignore", "fp"):
        # Format: ignore <file>:<line> [reason]
        parts = raw_args.split(None, 1)
        if ":" in (parts[0] if parts else ""):
            loc_parts = parts[0].split(":", 1)
            return {
                "file": loc_parts[0],
                "line": int(loc_parts[1]) if loc_parts[1].isdigit() else None,
                "reason": parts[1] if len(parts) > 1 else "",
            }
        return {"target": raw_args}

    if cmd == "rescan":
        return {"force": "--force" in raw_args}

    if cmd == "retroscan":
        # Format: retroscan [days=N] [limit=N]
        days_match = re.search(r"days=(\d+)", raw_args)
        limit_match = re.search(r"limit=(\d+)", raw_args)
        return {
            "days": int(days_match.group(1)) if days_match else 30,
            "limit": int(limit_match.group(1)) if limit_match else 50,
        }

    if cmd in ("approve", "reject"):
        return {"reason": raw_args}

    return {"raw": raw_args}


async def execute_command(
    command: str,
    args: dict[str, Any],
    context: dict[str, Any],
) -> str:
    """Execute a parsed @secbot command.

    Args:
        command: Command name.
        args: Parsed command arguments.
        context: PR context dict (repo_id, pr_id, pr_number, user, etc.).

    Returns:
        Response message string.
    """
    log.info("commands.execute", command=command, args=args, context_keys=list(context.keys()))

    handlers = {
        "help": _cmd_help,
        "rescan": _cmd_rescan,
        "ignore": _cmd_ignore,
        "fp": _cmd_false_positive,
        "status": _cmd_status,
        "findings": _cmd_findings,
        "approve": _cmd_approve,
        "reject": _cmd_reject,
        "retroscan": _cmd_retroscan,
        "summary": _cmd_summary,
        "unknown": _cmd_unknown,
    }

    handler = handlers.get(command, _cmd_unknown)
    return await handler(args, context)


async def _cmd_help(args: dict, ctx: dict) -> str:
    lines = ["**Available @secbot commands:**", ""]
    for cmd, desc in COMMANDS.items():
        lines.append(f"- `@secbot {cmd}` — {desc}")
    return "\n".join(lines)


async def _cmd_unknown(args: dict, ctx: dict) -> str:
    attempted = args.get("attempted_cmd", "")
    if attempted:
        return f"Unknown command: `{attempted}`. Type `@secbot help` to see available commands."
    return "I didn't understand that. Type `@secbot help` to see available commands."


async def _cmd_rescan(args: dict, ctx: dict) -> str:
    """Trigger a fresh scan of the current PR.

    Re-fetches access token, repo slug and head SHA from the database so the
    worker has everything it needs to fetch the diff (otherwise the scan
    silently fails inside the worker).
    """
    from cryptography.fernet import Fernet

    from aegis.config import get_settings
    from aegis.db.models import PullRequest, Repository
    from aegis.db.session import get_session_factory
    from aegis.worker.graph_worker import enqueue_scan
    from sqlalchemy import select

    pr_id = ctx.get("pr_id")
    pr_number = ctx.get("pr_number")
    repo_id = ctx.get("repo_id")

    if not repo_id or pr_number is None:
        return "❌ Missing PR context — cannot rescan."

    try:
        settings = get_settings()
        fernet = Fernet(settings.fernet_key.encode())

        repo_full_name = ctx.get("repo_full_name", "")
        access_token = ctx.get("access_token", "")
        provider = ctx.get("provider", "github")
        head_sha = ""

        # Always hydrate from DB so we have a fresh head SHA + decrypted token.
        session_factory = get_session_factory()
        async with session_factory() as session:
            repo_pk = int(repo_id) if str(repo_id).isdigit() else None
            if repo_pk is not None:
                repo = (await session.execute(
                    select(Repository).where(Repository.id == repo_pk)
                )).scalar_one_or_none()
                if repo is not None:
                    repo_full_name = repo_full_name or repo.slug
                    provider = provider or (
                        repo.provider.value if hasattr(repo.provider, "value") else str(repo.provider)
                    )
                    if not access_token and repo.token_encrypted:
                        try:
                            access_token = fernet.decrypt(repo.token_encrypted.encode()).decode()
                        except Exception:
                            access_token = ""

            if pr_id and str(pr_id).isdigit():
                pr_row = (await session.execute(
                    select(PullRequest).where(PullRequest.id == int(pr_id))
                )).scalar_one_or_none()
                if pr_row is not None:
                    meta = pr_row.analysis_metadata or {}
                    head_sha = meta.get("head_sha", "") or head_sha

        job_id = await enqueue_scan(
            repo_id=str(repo_id),
            pr_id=str(pr_id) if pr_id else None,
            pr_number=int(pr_number),
            repo_full_name=repo_full_name,
            access_token=access_token,
            head_sha=head_sha,
            provider=provider,
            pr_metadata={"number": int(pr_number), "head_sha": head_sha},
            force=args.get("force", False),
        )
        return f"🔄 Re-scan queued (job: `{job_id}`). Results will be posted when complete."
    except Exception as exc:
        log.error("commands.rescan_error", error=str(exc))
        return "❌ Failed to queue re-scan. Please try again later."


async def _cmd_ignore(args: dict, ctx: dict) -> str:
    file_path = args.get("file", "")
    line = args.get("line")
    repo_id = ctx.get("repo_id")

    if not file_path:
        return "Usage: `@secbot ignore <file>:<line> [reason]`"

    try:
        from datetime import datetime, timezone

        from aegis.db.models import FalsePositive
        from aegis.db.session import get_session_factory

        repo_pk: int | None
        try:
            repo_pk = int(repo_id) if repo_id is not None else None
        except (TypeError, ValueError):
            repo_pk = None
        if repo_pk is None:
            return "❌ Cannot save ignore rule without a numeric repo_id."

        session_factory = get_session_factory()
        async with session_factory() as session:
            async with session.begin():
                fp = FalsePositive(
                    repo_id=repo_pk,
                    pattern=f"{file_path}:{line}" if line else file_path,
                    directory=file_path.rsplit("/", 1)[0] if "/" in file_path else None,
                    created_at=datetime.now(timezone.utc),
                )
                session.add(fp)

        return f"✅ Finding at `{file_path}:{line}` will be ignored in future scans."
    except Exception as exc:
        log.error("commands.ignore_error", error=str(exc))
        return "❌ Failed to save ignore rule."


async def _cmd_false_positive(args: dict, ctx: dict) -> str:
    return await _cmd_ignore(args, ctx)


async def _cmd_status(args: dict, ctx: dict) -> str:
    from aegis.db.models import GraphExecution
    from aegis.db.session import get_session_factory
    from sqlalchemy import select

    pr_id = ctx.get("pr_id")

    pr_pk: int | None
    try:
        pr_pk = int(pr_id) if pr_id is not None else None
    except (TypeError, ValueError):
        pr_pk = None

    if pr_pk is None:
        return "No PR context available."

    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            result = await session.execute(
                select(GraphExecution)
                .where(GraphExecution.pr_id == pr_pk)
                .order_by(GraphExecution.started_at.desc())
                .limit(1)
            )
            execution = result.scalar_one_or_none()

        if not execution:
            return "No scan found for this PR."

        status_emoji = {
            "completed": "✅",
            "running": "🔄",
            "failed": "❌",
            "interrupted": "⏸️",
            "resumed": "▶️",
        }.get(execution.status, "❓")

        return (
            f"{status_emoji} **Scan Status**: {execution.status}\n"
            f"- **Scan ID**: `{execution.scan_id}`\n"
            f"- **Current Node**: {execution.current_node or 'N/A'}\n"
            f"- **Started**: {execution.started_at.strftime('%Y-%m-%d %H:%M UTC') if execution.started_at else 'N/A'}"
        )
    except Exception as exc:
        return f"❌ Failed to get status: {exc}"


async def _cmd_findings(args: dict, ctx: dict) -> str:
    from aegis.db.models import Finding
    from aegis.db.session import get_session_factory
    from sqlalchemy import select

    pr_id = ctx.get("pr_id")
    pr_pk: int | None
    try:
        pr_pk = int(pr_id) if pr_id is not None else None
    except (TypeError, ValueError):
        pr_pk = None
    if pr_pk is None:
        return "No PR context available."

    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            result = await session.execute(
                select(Finding)
                .where(Finding.pr_id == pr_pk)
                .order_by(Finding.created_at.desc())
                .limit(20)
            )
            findings = result.scalars().all()
        # Sort by severity in Python so 'critical' shows first.
        _SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        findings = sorted(findings, key=lambda f: -_SEV.get(f.severity, 0))

        if not findings:
            return "✅ No findings for this PR."

        lines = [f"**{len(findings)} findings:**", ""]
        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for f in findings:
            emoji = severity_emoji.get(f.severity, "⚪")
            lines.append(f"{emoji} `{f.file_path}:{f.line_number}` — {f.vuln_type} ({f.severity})")

        return "\n".join(lines)
    except Exception as exc:
        return f"❌ Failed to get findings: {exc}"


async def _cmd_approve(args: dict, ctx: dict) -> str:
    return await _handle_human_decision("approve", args, ctx)


async def _cmd_reject(args: dict, ctx: dict) -> str:
    return await _handle_human_decision("reject", args, ctx)


async def _handle_human_decision(decision: str, args: dict, ctx: dict) -> str:
    from datetime import datetime, timezone

    from aegis.db.models import GraphExecution, GraphStatusEnum, HumanDecisionEnum, HumanReview
    from aegis.db.session import get_session_factory
    from aegis.graph.runtime import resume_graph
    from sqlalchemy import select, update

    scan_id = ctx.get("scan_id")
    pr_id = ctx.get("pr_id")
    reviewer = ctx.get("user", "unknown")
    reason = args.get("reason", "")

    # If no scan_id in context, look up the latest scan for this PR so a user
    # can /approve a PR without knowing the scan ID.
    if not scan_id and pr_id:
        try:
            session_factory = get_session_factory()
            async with session_factory() as session:
                pr_pk = int(pr_id) if str(pr_id).isdigit() else None
                if pr_pk is not None:
                    row = (await session.execute(
                        select(GraphExecution)
                        .where(GraphExecution.pr_id == pr_pk)
                        .order_by(GraphExecution.started_at.desc())
                        .limit(1)
                    )).scalar_one_or_none()
                    if row is not None:
                        scan_id = row.scan_id
        except Exception:
            pass

    try:
        decision_enum = HumanDecisionEnum(decision)
    except ValueError:
        return f"❌ Unknown decision: {decision}"

    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            async with session.begin():
                hr = HumanReview(
                    scan_id=scan_id or "",
                    decision=decision_enum,
                    reviewer=reviewer,
                    rationale=reason or None,
                    created_at=datetime.now(timezone.utc),
                )
                session.add(hr)

                if scan_id:
                    await session.execute(
                        update(GraphExecution)
                        .where(GraphExecution.scan_id == scan_id)
                        .values(
                            status=GraphStatusEnum.resumed,
                            resumed_count=GraphExecution.resumed_count + 1,
                        )
                    )

        # Resume the graph with the decision (best-effort, may not be paused)
        if scan_id:
            try:
                await resume_graph(scan_id=str(scan_id), update={"human_decision": decision})
            except Exception as exc:
                log.warning("commands.resume_warning", scan_id=scan_id, error=str(exc))

        emoji = "✅" if decision == "approve" else "❌"
        return f"{emoji} PR **{decision}d** by @{reviewer}" + (f"\n> {reason}" if reason else "")
    except Exception as exc:
        log.error("commands.decision_error", error=str(exc))
        return f"❌ Failed to record decision: {exc}"


async def _cmd_retroscan(args: dict, ctx: dict) -> str:
    from aegis.graph.subgraphs.retro_scan import run_retro_scan

    repo_id = ctx.get("repo_id")
    if not repo_id:
        return "❌ No repository context available."

    days = args.get("days", 30)
    limit = args.get("limit", 50)

    try:
        summary = await run_retro_scan(repo_id=repo_id, days_back=days, limit=limit)
        return (
            f"🔍 Retro scan initiated!\n"
            f"- **PRs found**: {summary.get('total_prs', 0)}\n"
            f"- **Queued for scan**: {summary.get('queued_for_scan', 0)}\n"
            f"- Results will be posted as scans complete."
        )
    except Exception as exc:
        return f"❌ Failed to start retro scan: {exc}"


async def _cmd_summary(args: dict, ctx: dict) -> str:
    from aegis.db.models import PullRequest
    from aegis.db.session import get_session_factory
    from sqlalchemy import select

    pr_id = ctx.get("pr_id")
    pr_pk: int | None
    try:
        pr_pk = int(pr_id) if pr_id is not None else None
    except (TypeError, ValueError):
        pr_pk = None
    if pr_pk is None:
        return "No PR context."

    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            result = await session.execute(
                select(PullRequest).where(PullRequest.id == pr_pk)
            )
            pr = result.scalar_one_or_none()

        if not pr:
            return "PR not found."

        risk_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "green": "✅"}.get(
            getattr(pr, "risk_label", "green"), "❓"
        )
        return (
            f"**Security Summary for PR #{pr.pr_number}**\n\n"
            f"{risk_emoji} **Risk**: {getattr(pr, 'risk_label', 'N/A')} (score: {getattr(pr, 'risk_score', 0)}/100)\n"
            f"- **Findings**: {getattr(pr, 'findings_count', 0)}\n"
            f"- **Policy**: {(pr.analysis_metadata or {}).get('policy_decision', 'N/A')}"
        )
    except Exception as exc:
        return f"❌ Failed to get summary: {exc}"
