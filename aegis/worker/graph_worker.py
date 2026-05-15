"""Arq task: run the LangGraph security analysis pipeline for a PR."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

from aegis.observability.logging import get_logger

log = get_logger(__name__)

_GRAPH_TIMEOUT_SECONDS = 600  # 10 minutes max per scan
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

        # Execute graph with timeout
        from aegis.graph.runtime import execute_graph

        result = await asyncio.wait_for(
            execute_graph(
                initial_state=initial_state,
                thread_id=scan_id,
            ),
            timeout=_GRAPH_TIMEOUT_SECONDS,
        )

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

    except asyncio.TimeoutError:
        log.error("worker.timeout", scan_id=scan_id)
        await _update_scan_status(scan_id, "failed", error="Scan timeout exceeded")
        return {"scan_id": scan_id, "status": "failed", "error": "timeout"}

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

    vcs = get_provider(provider, access_token)

    # Fetch diff files
    diff_files = await vcs.get_pr_files(repo=repo_full_name, pr_number=pr_number)
    full_diff = await vcs.get_pr_diff(repo=repo_full_name, pr_number=pr_number)

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
        from aegis.db.models import GraphExecution
        from sqlalchemy import update

        session_factory = get_session_factory()
        async with session_factory() as session:
            async with session.begin():
                update_values = {
                    "status": status,
                    "updated_at": datetime.now(timezone.utc),
                }
                if status == "completed":
                    update_values["completed_at"] = datetime.now(timezone.utc)

                await session.execute(
                    update(GraphExecution)
                    .where(GraphExecution.scan_id == scan_id)
                    .values(**update_values)
                )
    except Exception as exc:
        log.warning("worker.db_update_error", scan_id=scan_id, error=str(exc))
