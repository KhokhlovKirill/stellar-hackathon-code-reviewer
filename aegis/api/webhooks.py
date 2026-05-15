<<<<<<< Updated upstream
"""Webhook gateway (criterion C1).

Order of operations is security-critical:
  1. read RAW body (size-capped)              4. resolve webhook secret
  2. JSON-parse for identification only       5. verify signature over RAW body
  3. classify event (no side effects yet)     6. idempotency claim, then enqueue

Nothing with side effects happens before signature verification. JSON parsing for
identification is safe (we never act on unverified content). Ack is <1s: the worker
does all heavy work.
"""

from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from aegis.db import get_session
from aegis.db.models import Scan
from aegis.errors import WebhookPayloadError, WebhookVerificationError
from aegis.idempotency import claim
from aegis.obs import bind_scan, get_logger, metrics
from aegis.providers import get_provider
from aegis.providers.signatures import verify
from aegis.queue import enqueue_dialog, enqueue_scan
from aegis.repos import webhook_secret
from aegis.schemas import EventKind, Provider

router = APIRouter(prefix="/webhooks", tags=["webhooks"])
log = get_logger("aegis.webhook")

_MAX_BODY = None  # resolved lazily from config


def _headers(request: Request) -> dict[str, str]:
    return {k.lower(): v for k, v in request.headers.items()}


@router.post("/{provider}")
async def receive(provider: str, request: Request) -> JSONResponse:
    from aegis.config import get_config

    try:
        prov = Provider(provider)
    except ValueError:
        return JSONResponse({"error": "unknown provider"}, status_code=404)

    cfg = get_config().service
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type.lower():
        return JSONResponse({"error": "unsupported content type"}, status_code=415)

    raw = await request.body()
    if len(raw) > cfg.max_webhook_body_bytes:
        return JSONResponse({"error": "payload too large"}, status_code=413)

    headers = _headers(request)
    impl = get_provider(prov)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return JSONResponse({"error": "invalid json"}, status_code=400)

    # --- classify (no side effects) ---
    try:
        ev = impl.parse_event(headers, payload)
    except WebhookPayloadError as exc:
        # Unknown/benign event (ping, unhandled). Still authenticate, then ack so
        # the provider does not retry.
        repo_ext = str(payload.get("repository", {}).get("id") or
                        payload.get("project", {}).get("id") or
                        payload.get("repository", {}).get("uuid") or "")
        try:
            verify(prov, raw, headers, await webhook_secret(prov, repo_ext))
        except WebhookVerificationError:
            metrics.webhooks_total.labels(prov.value, "rejected", "false").inc()
            return JSONResponse({"error": "signature verification failed"}, status_code=401)
        log.info("webhook.ignored", provider=prov.value, reason=str(exc))
        metrics.webhooks_total.labels(prov.value, "ignored", "true").inc()
        return JSONResponse({"status": "ignored"}, status_code=202)

    # --- verify signature over RAW body ---
    try:
        secret = await webhook_secret(prov, ev.repo_external_id)
        verify(prov, raw, headers, secret)
    except WebhookVerificationError as exc:
        log.warning("webhook.bad_signature", provider=prov.value, repo=ev.repo_slug)
        metrics.webhooks_total.labels(prov.value, ev.kind.value, "false").inc()
        return JSONResponse({"error": f"signature: {exc}"}, status_code=401)

    metrics.webhooks_total.labels(prov.value, ev.kind.value, "true").inc()

    if ev.kind is EventKind.IGNORED:
        return JSONResponse({"status": "ignored"}, status_code=202)

    if ev.kind is EventKind.COMMENT:
        # Dialog (C7) — handled by the worker; idempotent on comment_id.
        if await claim(ev.dedupe_key()):
            await enqueue_dialog(ev.model_dump_json())
        return JSONResponse({"status": "queued", "kind": "dialog"}, status_code=202)

    # --- PR opened/updated: idempotency then enqueue scan ---
    if not await claim(ev.dedupe_key()):
        log.info("webhook.duplicate", provider=prov.value, repo=ev.repo_slug,
                 pr=ev.pr_id, head=ev.head_sha)
        return JSONResponse({"status": "duplicate"}, status_code=202)

    scan_id = uuid.uuid4().hex
    bind_scan(scan_id=scan_id, provider=prov.value, repo=ev.repo_slug,
              pr=ev.pr_id, head_sha=ev.head_sha or "")
    async with get_session() as s:
        s.add(Scan(
            id=scan_id, provider=prov.value, repo_slug=ev.repo_slug,
            pr_id=ev.pr_id, head_sha=ev.head_sha or "", status="queued",
        ))
    await enqueue_scan(scan_id, ev)
    log.info("webhook.received", kind=ev.kind.value, scan_id=scan_id,
             repo=ev.repo_slug, pr=ev.pr_id)
    return JSONResponse({"status": "queued", "scan_id": scan_id}, status_code=202)
=======
"""Webhook endpoints for GitHub and GitLab with HMAC-SHA256 verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from aegis.db.session import get_db
from aegis.db.models import Repository, PullRequest, GraphExecution
from aegis.observability.logging import get_logger
from aegis.observability.metrics import WEBHOOKS_RECEIVED

log = get_logger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Events we care about
_GITHUB_PR_EVENTS = {"opened", "reopened", "synchronize", "closed"}
_GITLAB_PR_EVENTS = {"open", "reopen", "update", "close"}


# ── HMAC Verification ─────────────────────────────────────────────────────────

def _verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub HMAC-SHA256 webhook signature."""
    if not signature or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _verify_gitlab_token(token: str, secret: str) -> bool:
    """Verify GitLab secret token header."""
    return hmac.compare_digest(token or "", secret)


# ── GitHub Webhook ────────────────────────────────────────────────────────────

@router.post("/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    x_github_event: Annotated[str | None, Header()] = None,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_delivery: Annotated[str | None, Header()] = None,
):
    """Receive and process GitHub webhook events."""
    body = await request.body()
    WEBHOOKS_RECEIVED.labels(provider="github", event=x_github_event or "unknown").inc()

    if x_github_event != "pull_request":
        log.debug("github.webhook.ignored", event=x_github_event)
        return {"status": "ignored", "event": x_github_event}

    # Parse payload
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    action = payload.get("action", "")
    if action not in _GITHUB_PR_EVENTS:
        return {"status": "ignored", "action": action}

    # Find repository
    repo_data = payload.get("repository", {})
    repo_full_name = repo_data.get("full_name", "")

    repo = await _get_repo(db, provider="github", full_name=repo_full_name)
    if not repo:
        log.warning("github.webhook.repo_not_found", repo=repo_full_name)
        raise HTTPException(status_code=404, detail=f"Repository {repo_full_name} not registered")

    # Verify HMAC signature
    if repo.webhook_secret:
        secret = _decrypt_secret(repo.webhook_secret)
        if not _verify_github_signature(body, x_hub_signature_256 or "", secret):
            log.warning("github.webhook.invalid_signature", repo=repo_full_name)
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    pr_data = payload.get("pull_request", {})
    pr_number = pr_data.get("number")
    head_sha = pr_data.get("head", {}).get("sha", "")

    if action == "closed":
        # Update PR status
        await _update_pr_status(db, repo.id, pr_number, "closed")
        return {"status": "ok", "action": "closed"}

    # Upsert PR record
    pr = await _upsert_pr(
        db,
        repo_id=repo.id,
        pr_number=pr_number,
        head_sha=head_sha,
        title=pr_data.get("title", ""),
        description=pr_data.get("body", "") or "",
        author=pr_data.get("user", {}).get("login", ""),
        base_branch=pr_data.get("base", {}).get("ref", ""),
        head_branch=pr_data.get("head", {}).get("ref", ""),
    )

    # Create GraphExecution record
    scan_id = str(uuid.uuid4())
    execution = GraphExecution(
        id=uuid.uuid4(),
        scan_id=scan_id,
        pr_id=pr.id,
        repo_id=repo.id,
        status="queued",
        created_at=datetime.now(timezone.utc),
    )
    db.add(execution)
    await db.commit()

    # Queue the scan via background task
    background_tasks.add_task(
        _enqueue_scan,
        repo_id=str(repo.id),
        pr_id=str(pr.id),
        pr_number=pr_number,
        scan_id=scan_id,
        repo_full_name=repo_full_name,
        access_token=_decrypt_secret(repo.access_token) if repo.access_token else "",
        head_sha=head_sha,
        provider="github",
        pr_metadata={
            "number": pr_number,
            "title": pr_data.get("title", ""),
            "description": pr_data.get("body", "") or "",
            "head_sha": head_sha,
            "base_branch": pr_data.get("base", {}).get("ref", ""),
            "head_branch": pr_data.get("head", {}).get("ref", ""),
            "author": pr_data.get("user", {}).get("login", ""),
            "node_id": pr_data.get("node_id"),
            "id": pr_data.get("id"),
        },
    )

    log.info("github.webhook.queued", repo=repo_full_name, pr=pr_number, scan_id=scan_id)
    return {"status": "queued", "scan_id": scan_id, "pr": pr_number}


# ── GitLab Webhook ────────────────────────────────────────────────────────────

@router.post("/gitlab")
async def gitlab_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    x_gitlab_event: Annotated[str | None, Header()] = None,
    x_gitlab_token: Annotated[str | None, Header()] = None,
):
    """Receive and process GitLab webhook events."""
    body = await request.body()
    WEBHOOKS_RECEIVED.labels(provider="gitlab", event=x_gitlab_event or "unknown").inc()

    if x_gitlab_event != "Merge Request Hook":
        log.debug("gitlab.webhook.ignored", event=x_gitlab_event)
        return {"status": "ignored", "event": x_gitlab_event}

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    mr = payload.get("object_attributes", {})
    action = mr.get("action", "")
    if action not in _GITLAB_PR_EVENTS:
        return {"status": "ignored", "action": action}

    project = payload.get("project", {})
    repo_full_name = project.get("path_with_namespace", "")

    repo = await _get_repo(db, provider="gitlab", full_name=repo_full_name)
    if not repo:
        raise HTTPException(status_code=404, detail=f"Repository {repo_full_name} not registered")

    # Verify token
    if repo.webhook_secret:
        secret = _decrypt_secret(repo.webhook_secret)
        if not _verify_gitlab_token(x_gitlab_token or "", secret):
            raise HTTPException(status_code=401, detail="Invalid webhook token")

    pr_number = mr.get("iid")
    head_sha = mr.get("last_commit", {}).get("id", "")

    if action == "close":
        await _update_pr_status(db, repo.id, pr_number, "closed")
        return {"status": "ok", "action": "closed"}

    pr = await _upsert_pr(
        db,
        repo_id=repo.id,
        pr_number=pr_number,
        head_sha=head_sha,
        title=mr.get("title", ""),
        description=mr.get("description", "") or "",
        author=payload.get("user", {}).get("username", ""),
        base_branch=mr.get("target_branch", ""),
        head_branch=mr.get("source_branch", ""),
    )

    scan_id = str(uuid.uuid4())
    execution = GraphExecution(
        id=uuid.uuid4(),
        scan_id=scan_id,
        pr_id=pr.id,
        repo_id=repo.id,
        status="queued",
        created_at=datetime.now(timezone.utc),
    )
    db.add(execution)
    await db.commit()

    background_tasks.add_task(
        _enqueue_scan,
        repo_id=str(repo.id),
        pr_id=str(pr.id),
        pr_number=pr_number,
        scan_id=scan_id,
        repo_full_name=repo_full_name,
        access_token=_decrypt_secret(repo.access_token) if repo.access_token else "",
        head_sha=head_sha,
        provider="gitlab",
        pr_metadata={
            "number": pr_number,
            "title": mr.get("title", ""),
            "description": mr.get("description", "") or "",
            "head_sha": head_sha,
            "base_branch": mr.get("target_branch", ""),
            "head_branch": mr.get("source_branch", ""),
            "author": payload.get("user", {}).get("username", ""),
            "id": mr.get("id"),
        },
    )

    log.info("gitlab.webhook.queued", repo=repo_full_name, pr=pr_number, scan_id=scan_id)
    return {"status": "queued", "scan_id": scan_id, "pr": pr_number}


# ── Comment Webhook (ChatOps) ─────────────────────────────────────────────────

@router.post("/github/comment")
async def github_comment_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    x_github_event: Annotated[str | None, Header()] = None,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
):
    """Handle GitHub PR comment webhooks for @secbot commands."""
    if x_github_event not in ("issue_comment", "pull_request_review_comment"):
        return {"status": "ignored"}

    body = await request.body()
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    comment_body = payload.get("comment", {}).get("body", "")
    if "@secbot" not in comment_body.lower():
        return {"status": "ignored", "reason": "no @secbot mention"}

    pr_number = payload.get("issue", {}).get("number") or payload.get("pull_request", {}).get("number")
    repo_full_name = payload.get("repository", {}).get("full_name", "")

    repo = await _get_repo(db, provider="github", full_name=repo_full_name)
    if not repo:
        return {"status": "ignored", "reason": "repo not registered"}

    pr = await _get_pr(db, repo.id, pr_number)

    context = {
        "repo_id": str(repo.id),
        "pr_id": str(pr.id) if pr else None,
        "pr_number": pr_number,
        "repo_full_name": repo_full_name,
        "user": payload.get("comment", {}).get("user", {}).get("login", ""),
    }

    background_tasks.add_task(_handle_chatops_command, comment_body, context)
    return {"status": "processing"}


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_repo(db: AsyncSession, provider: str, full_name: str):
    from sqlalchemy import select
    result = await db.execute(
        select(Repository).where(
            Repository.provider == provider,
            Repository.full_name == full_name,
        )
    )
    return result.scalar_one_or_none()


async def _get_pr(db: AsyncSession, repo_id, pr_number: int):
    from sqlalchemy import select
    result = await db.execute(
        select(PullRequest).where(
            PullRequest.repo_id == repo_id,
            PullRequest.pr_number == pr_number,
        )
    )
    return result.scalar_one_or_none()


async def _upsert_pr(
    db: AsyncSession,
    repo_id,
    pr_number: int,
    head_sha: str,
    title: str,
    description: str,
    author: str,
    base_branch: str,
    head_branch: str,
) -> PullRequest:
    from sqlalchemy import select, update

    result = await db.execute(
        select(PullRequest).where(
            PullRequest.repo_id == repo_id,
            PullRequest.pr_number == pr_number,
        )
    )
    pr = result.scalar_one_or_none()

    if pr:
        await db.execute(
            update(PullRequest)
            .where(PullRequest.id == pr.id)
            .values(
                head_sha=head_sha,
                status="open",
                updated_at=datetime.now(timezone.utc),
            )
        )
    else:
        pr = PullRequest(
            id=uuid.uuid4(),
            repo_id=repo_id,
            pr_number=pr_number,
            head_sha=head_sha,
            title=title,
            description=description,
            author=author,
            base_branch=base_branch,
            head_branch=head_branch,
            status="open",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(pr)

    await db.flush()
    return pr


async def _update_pr_status(db: AsyncSession, repo_id, pr_number: int, status: str):
    from sqlalchemy import update
    await db.execute(
        update(PullRequest)
        .where(PullRequest.repo_id == repo_id, PullRequest.pr_number == pr_number)
        .values(status=status, updated_at=datetime.now(timezone.utc))
    )
    await db.commit()


def _decrypt_secret(encrypted: str | None) -> str:
    """Decrypt a Fernet-encrypted secret."""
    if not encrypted:
        return ""
    try:
        from aegis.config import get_settings
        from cryptography.fernet import Fernet
        settings = get_settings()
        f = Fernet(settings.fernet_key.encode())
        return f.decrypt(encrypted.encode()).decode()
    except Exception:
        return encrypted  # Return as-is if not encrypted


async def _enqueue_scan(
    repo_id: str,
    pr_id: str,
    pr_number: int,
    scan_id: str,
    repo_full_name: str,
    access_token: str,
    head_sha: str,
    provider: str,
    pr_metadata: dict,
):
    """Background task to enqueue a graph scan."""
    try:
        from aegis.worker.graph_worker import enqueue_scan
        await enqueue_scan(
            repo_id=repo_id,
            pr_id=pr_id,
            pr_number=pr_number,
            scan_id=scan_id,
            repo_full_name=repo_full_name,
            access_token=access_token,
            head_sha=head_sha,
            provider=provider,
            pr_metadata=pr_metadata,
        )
    except Exception as exc:
        log.error("webhooks.enqueue_error", scan_id=scan_id, error=str(exc))


async def _handle_chatops_command(message: str, context: dict):
    """Background task to process a @secbot command."""
    try:
        from aegis.graph.subgraphs.chatops import run_chatops
        from aegis.dialog.memory import append_message

        pr_id = context.get("pr_id", "")

        await append_message(pr_id, "user", message, {"user": context.get("user")})
        response = await run_chatops(message, context)
        await append_message(pr_id, "bot", response)

        # Post response back to PR
        provider_name = context.get("provider", "github")
        repo_full_name = context.get("repo_full_name", "")
        pr_number = context.get("pr_number")

        if repo_full_name and pr_number:
            from aegis.providers import get_provider
            provider = get_provider(provider_name, context.get("access_token", ""))
            await provider.post_comment(repo=repo_full_name, pr_number=pr_number, body=response)

    except Exception as exc:
        log.error("webhooks.chatops_error", error=str(exc))
>>>>>>> Stashed changes
