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
