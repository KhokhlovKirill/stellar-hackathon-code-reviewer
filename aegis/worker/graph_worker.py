"""Arq task: run the LangGraph security analysis pipeline for a PR."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from aegis.observability.logging import get_logger

log = get_logger(__name__)

# Must match WorkerSettings.queue_name in aegis.worker.main
ARQ_QUEUE_NAME = "aegis:queue"

_REDIS_POOL = None


async def get_redis_pool():
    """Lazy-init Redis connection pool."""
    global _REDIS_POOL
    if _REDIS_POOL is None:
        import arq
        from aegis.config import get_settings
        settings = get_settings()
        _REDIS_POOL = await arq.create_pool(arq.connections.RedisSettings.from_dsn(settings.redis_url))
    return _REDIS_POOL


async def enqueue_scan(
    repo_id: str,
    pr_id: str | None = None,
    pr_number: int | None = None,
    scan_id: str | None = None,
    repo_full_name: str = "",
    access_token: str = "",
    head_sha: str = "",
    provider: str = "github",
    pr_metadata: dict | None = None,
    force: bool = False,
    retro: bool = False,
) -> str:
    """Enqueue a PR security scan job via Arq.

    Returns:
        Job ID string.
    """
    pool = await get_redis_pool()
    scan_id = scan_id or str(uuid.uuid4())

    job = await pool.enqueue_job(
        "run_graph_scan",
        repo_id=repo_id,
        pr_id=pr_id,
        pr_number=pr_number,
        scan_id=scan_id,
        repo_full_name=repo_full_name,
        access_token=access_token,
        head_sha=head_sha,
        provider=provider,
        pr_metadata=pr_metadata or {},
        force=force,
        retro=retro,
        _job_id=scan_id,
        _queue_name=ARQ_QUEUE_NAME,
    )

    log.info("worker.enqueued", scan_id=scan_id, repo=repo_full_name, pr=pr_number)
    return scan_id


async def run_graph_scan(
    ctx: dict,
    repo_id: str,
    pr_id: str | None,
    pr_number: int | None,
    scan_id: str,
    repo_full_name: str,
    access_token: str,
    head_sha: str,
    provider: str,
    pr_metadata: dict,
    force: bool = False,
    retro: bool = False,
) -> dict[str, Any]:
    """Arq task: fetch PR diff and run the security analysis graph.

    This is the main worker task executed by Arq workers.
    """
    log.info(
        "worker.task_start",
        scan_id=scan_id,
        repo=repo_full_name,
        pr=pr_number,
        retro=retro,
    )

    # Update scan status in DB
    await _update_scan_status(scan_id, "running")

    try:
        # Fetch PR diff and file list from provider
        diff_files, full_diff, repo_settings = await _fetch_pr_data(
            provider=provider,
            access_token=access_token,
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            head_sha=head_sha,
        )

        # Build initial graph state
        from aegis.graph.state import SecurityGraphState

        initial_state: SecurityGraphState = {
            "scan_id": scan_id,
            "pr_id": pr_id,
            "repo_id": repo_id,
            "repo_full_name": repo_full_name,
            "provider": provider,
            "access_token": access_token,
            "pr_number": pr_number,
            "pr_metadata": {**pr_metadata, "head_sha": head_sha},
            "diff_files": diff_files,
            "full_diff": full_diff,
            "repo_settings": repo_settings,
            # Outputs (initially empty)
            "action": None,
            "file_classifications": {},
            "filtered_files": [],
            "ast_context": {},
            "import_graph": {},
            "rag_context": [],
            "deterministic_findings": [],
            "has_secret": False,
            "scanner_errors": {},
            "llm_a_findings": [],
            "llm_b_findings": [],
            "final_findings": [],
            "risk_score": 0,
            "risk_label": "green",
            "blast_radius": {},
            "human_review_pending": False,
            "human_decision": None,
            "policy_decision": "pass",
            "policy_reasons": [],
            "autofix_suggestions": [],
            "pr_comment_body": "",
            "inline_comments": [],
            "status_check": {},
            "published": False,
        }

        # Execute graph — execute_graph() manages its own timeout internally
        # (settings.max_graph_execution_seconds) and returns an error dict on
        # timeout rather than raising, so we must inspect the result status.
        from aegis.graph.runtime import execute_graph

        result = await execute_graph(initial_state=initial_state)

        # Detect internal graph errors (timeout, exception caught inside runtime)
        if result.get("status") == "error":
            error_msg = result.get("error_message", "Graph execution failed")
            log.error("worker.graph_internal_error", scan_id=scan_id, error=error_msg)
            await _update_scan_status(scan_id, "failed", error=error_msg)
            return {"scan_id": scan_id, "status": "failed", "error": error_msg}

        if result.get("status") == "interrupted":
            log.info(
                "worker.graph_interrupted",
                scan_id=scan_id,
                pending_human=result.get("human_review_pending"),
            )
            await _update_scan_status(scan_id, "interrupted")
            return {
                "scan_id": scan_id,
                "status": "interrupted",
                "human_review_pending": result.get("human_review_pending", True),
            }

        final_risk = result.get("risk_label", "green")
        finding_count = len(result.get("final_findings", []))

        log.info(
            "worker.task_complete",
            scan_id=scan_id,
            risk=final_risk,
            findings=finding_count,
        )

        return {
            "scan_id": scan_id,
            "status": "completed",
            "risk_label": final_risk,
            "findings": finding_count,
        }

    except Exception as exc:
        log.error("worker.task_error", scan_id=scan_id, error=str(exc))
        await _update_scan_status(scan_id, "failed", error=str(exc))
        raise


async def _fetch_pr_data(
    provider: str,
    access_token: str,
    repo_full_name: str,
    pr_number: int | None,
    head_sha: str,
) -> tuple[list[dict], str, dict]:
    """Fetch diff files, full diff text, and repo settings from VCS provider."""
    from aegis.providers import get_provider
    from aegis.db.session import get_session_factory
    from aegis.db.models import Repository
    from sqlalchemy import select

    vcs = get_provider(provider, access_token, repo_full_name)

    # Fetch diff via BaseProvider.fetch_diff (one round-trip; serialise for LangGraph state)
    async with vcs:
        if pr_number is None:
            diff_objs = []
        else:
            diff_objs = await vcs.fetch_diff(pr_number)

    diff_files = [
        {
            "filename": f.filename,
            "status": f.status,
            "patch": f.patch,
            "additions": f.additions,
            "deletions": f.deletions,
            "raw_url": f.raw_url,
            "blob_url": f.blob_url,
            "sha": f.sha,
            "language": f.language,
        }
        for f in diff_objs
    ]
    full_diff = "\n".join(f.patch for f in diff_objs if f.patch)

    # Load repo settings from DB
    repo_settings = {}
    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            from aegis.db.models import ProviderEnum

            try:
                provider_enum = ProviderEnum(provider)
            except ValueError:
                provider_enum = None

            if provider_enum is not None:
                result = await session.execute(
                    select(Repository).where(
                        Repository.slug == repo_full_name,
                        Repository.provider == provider_enum,
                    )
                )
            else:
                result = await session.execute(
                    select(Repository).where(Repository.slug == repo_full_name)
                )
            repo = result.scalar_one_or_none()
            if repo and repo.settings_json:
                repo_settings = repo.settings_json
    except Exception as exc:
        log.warning("worker.settings_fetch_error", error=str(exc))

    return diff_files, full_diff, repo_settings


async def _update_scan_status(scan_id: str, status: str, error: str | None = None):
    """Update GraphExecution status in the database."""
    try:
        from aegis.db.session import get_session_factory
        from aegis.db.models import GraphExecution, GraphStatusEnum
        from sqlalchemy import select

        # Worker uses string statuses; DB column is GraphStatusEnum (VARCHAR).
        if status == "completed":
            mapped = GraphStatusEnum.completed
        elif status == "failed":
            mapped = GraphStatusEnum.failed
        elif status == "running":
            mapped = GraphStatusEnum.running
        elif status == "interrupted":
            mapped = GraphStatusEnum.interrupted
        else:
            mapped = GraphStatusEnum.failed

        session_factory = get_session_factory()
        async with session_factory() as session:
            async with session.begin():
                res = await session.execute(
                    select(GraphExecution).where(GraphExecution.scan_id == scan_id)
                )
                row = res.scalar_one_or_none()
                if row is None:
                    return

                now = datetime.now(timezone.utc)
                row.status = mapped
                if mapped in (
                    GraphStatusEnum.completed,
                    GraphStatusEnum.failed,
                    GraphStatusEnum.interrupted,
                ):
                    row.finished_at = now
                if error is not None and mapped == GraphStatusEnum.failed:
                    meta = dict(row.metadata_json or {})
                    meta["last_error"] = error
                    row.metadata_json = meta
    except Exception as exc:
        log.warning("worker.db_update_error", scan_id=scan_id, error=str(exc))
