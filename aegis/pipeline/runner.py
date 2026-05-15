"""Scan pipeline orchestrator.

Stages run in order; each later phase fills in its stage module. A stage that is
not yet present is logged and skipped (incremental delivery of a fixed architecture,
not an MVP shortcut — the contract/order is final). Phase 1 fully implements:
rehydrate event → resolve repo → fetch PR → fetch diff (changed-only) → C2 analytics
→ persist. Stale (superseded by a newer commit) scans abort early.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

from sqlalchemy import update

from aegis.db import get_session
from aegis.db.models import Scan
from aegis.errors import ProviderError
from aegis.obs import bind_scan, get_logger, metrics
from aegis.providers import get_provider
from aegis.queue import is_stale
from aegis.redispool import redis
from aegis.repos import resolve
from aegis.schemas import FileChange, Provider, ScanResult, WebhookEvent
from aegis.tokenest import estimate_tokens

log = get_logger("aegis.pipeline")


async def _load_event(scan_id: str) -> WebhookEvent | None:
    raw = await redis().get(f"aegis:scan:{scan_id}:event")
    return WebhookEvent.model_validate_json(raw) if raw else None


def _diff_text(files: list[FileChange]) -> str:
    parts: list[str] = []
    for f in files:
        for h in f.hunks:
            parts.append(h.header)
            parts.extend(ln.content for ln in h.lines)
    return "\n".join(parts)


async def _finish(scan_id: str, result: ScanResult, status: str) -> None:
    result.finished_at = datetime.now(UTC)
    async with get_session() as s:
        await s.execute(
            update(Scan).where(Scan.id == scan_id).values(
                status=status,
                degraded=result.degraded,
                files_scanned=result.files_scanned,
                files_skipped=result.files_skipped,
                est_sent_tokens=result.est_sent_tokens,
                est_full_repo_tokens=result.est_full_repo_tokens,
                risk_score=result.risk_score,
                risk_label=result.risk_label,
                decision=result.decision.model_dump() if result.decision else {},
                finished_at=result.finished_at,
            )
        )
    metrics.queue_depth.dec()
    metrics.scans_total.labels(result.provider.value, status).inc()


async def run_scan_pipeline(scan_id: str) -> None:
    t0 = time.monotonic()
    ev = await _load_event(scan_id)
    if ev is None:
        log.error("scan.no_event", scan_id=scan_id)
        return

    bind_scan(scan_id=scan_id, provider=ev.provider.value, repo=ev.repo_slug,
              pr=ev.pr_id, head_sha=ev.head_sha or "")

    if await is_stale(ev.provider.value, ev.repo_external_id, ev.pr_id, ev.head_sha or ""):
        log.info("scan.superseded", scan_id=scan_id)
        result = ScanResult(
            scan_id=scan_id, provider=ev.provider, repo_slug=ev.repo_slug,
            pr_id=ev.pr_id, head_sha=ev.head_sha or "",
            started_at=datetime.now(UTC),
        )
        await _finish(scan_id, result, "superseded")
        return

    result = ScanResult(
        scan_id=scan_id, provider=ev.provider, repo_slug=ev.repo_slug,
        pr_id=ev.pr_id, head_sha=ev.head_sha or "",
        started_at=datetime.now(UTC),
    )
    async with get_session() as s:
        await s.execute(update(Scan).where(Scan.id == scan_id).values(status="running"))

    try:
        ctx = await resolve(ev.provider, ev.repo_external_id, ev.repo_slug)
        if not ctx.access_token:
            log.error("scan.no_token", scan_id=scan_id,
                      hint="register repo + token in Admin Portal (Phase 8)")
            await _finish(scan_id, result, "no_token")
            return

        provider = get_provider(ev.provider)
        pr = await provider.fetch_pull_request(ev, ctx.access_token)
        files = await provider.fetch_diff(pr, ctx.access_token)

        diff_text = _diff_text(files)
        result.est_sent_tokens = estimate_tokens(diff_text)
        result.est_full_repo_tokens = await _estimate_full_repo_tokens(
            ev.provider, pr.repo_slug, ctx.access_token
        )
        saved = max(0, result.est_full_repo_tokens - result.est_sent_tokens)
        if saved:
            metrics.tokens_saved_total.inc(saved)

        log.info(
            "diff.fetched", scan_id=scan_id, files=len(files),
            added_lines=sum(len(f.added_lines()) for f in files),
            diff_bytes=len(diff_text), est_sent_tokens=result.est_sent_tokens,
            est_full_repo_tokens=result.est_full_repo_tokens, tokens_saved=saved,
        )

        # ---- Later-phase stages (filter→deterministic→llm→render→policy) ----
        from aegis.pipeline.state import PipelineState

        state = PipelineState(
            scan_id=scan_id, ev=ev, pr=pr, ctx=ctx, result=result, files=files
        )
        await _run_optional_stages(state)

        await _finish(scan_id, result, "completed")
    except ProviderError as exc:
        log.error("scan.provider_error", scan_id=scan_id, error=str(exc))
        await _finish(scan_id, result, "provider_error")
    except Exception as exc:
        log.exception("scan.failed", scan_id=scan_id, error=str(exc))
        await _finish(scan_id, result, "error")
    finally:
        metrics.scan_duration.observe(time.monotonic() - t0)


async def _estimate_full_repo_tokens(provider: Provider, slug: str, token: str) -> int:
    """Best-effort estimate of what a *whole-repo* analysis would have cost, to
    quantify the diff-only saving (C2). Uses repo size metadata only (one cheap
    call); on any failure returns 0 (the honest core fact — repo never cloned —
    is still logged)."""
    try:
        impl = get_provider(provider)
        if provider is Provider.GITHUB:
            r = await impl._request("GET", f"/repos/{slug}", token, "repo_meta")  # type: ignore[attr-defined]
            if r.status_code == 200:
                return int(r.json().get("size", 0)) * 1024 // 4  # size is KB
    except Exception:
        return 0
    return 0


async def _run_optional_stages(state) -> None:  # type: ignore[no-untyped-def]
    """Invoke pipeline stages that exist; skip (with a log) those not yet built.

    Order is fixed by docs/03 §3. As each phase lands, its module appears and is
    picked up here without changing the orchestrator contract. Every stage has the
    same signature: `async def stage(state: PipelineState) -> None`.
    """
    stages = [
        ("filter", "aegis.pipeline.filter", "apply_filter"),
        ("context", "aegis.pipeline.context", "enrich_context"),
        ("deterministic", "aegis.pipeline.deterministic_stage", "run_deterministic"),
        ("llm", "aegis.pipeline.llm_stage", "run_llm_analysis"),
        ("suppression", "aegis.pipeline.suppression", "apply_suppression"),
        ("risk_score", "aegis.pipeline.risk_score", "compute_risk_score"),
        ("blast_radius", "aegis.pipeline.blast_radius", "generate_blast_radius"),
        ("autofix", "aegis.pipeline.autofix", "generate_autofix"),
        ("render", "aegis.pipeline.render", "render_and_post"),
        ("policy", "aegis.pipeline.policy", "apply_merge_policy"),
    ]
    for name, module_path, fn_name in stages:
        try:
            mod = __import__(module_path, fromlist=[fn_name])
            fn = getattr(mod, fn_name)
        except (ImportError, AttributeError):
            log.info("pipeline.stage_pending", scan_id=state.scan_id, stage=name)
            continue
        await fn(state)
