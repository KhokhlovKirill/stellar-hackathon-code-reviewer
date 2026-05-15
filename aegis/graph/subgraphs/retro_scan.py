"""Retro scan subgraph — re-scans historical PRs with updated rules."""

from __future__ import annotations

import uuid
from typing import Any

from langgraph.graph import END, StateGraph

from aegis.graph.state import RetroScanState
from aegis.observability.logging import get_logger

log = get_logger(__name__)


def _provider_str(provider: Any) -> str:
    return provider.value if hasattr(provider, "value") else str(provider)


async def fetch_prs_node(state: RetroScanState) -> RetroScanState:
    """Fetch historical PRs for retro scanning."""
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select

    from aegis.db.models import PullRequest
    from aegis.db.session import get_session_factory

    repo_db_id = state["repo_db_id"]
    days_back = state.get("days_back", 30)
    limit = state.get("limit", 50)

    log.info("retro_scan.fetch", repo_db_id=repo_db_id, days_back=days_back)

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)

        session_factory = get_session_factory()
        async with session_factory() as session:
            result = await session.execute(
                select(PullRequest)
                .where(
                    PullRequest.repo_id == repo_db_id,
                    PullRequest.created_at >= cutoff,
                )
                .order_by(PullRequest.created_at.desc())
                .limit(limit)
            )
            prs = result.scalars().all()
            pr_list = [{"id": str(pr.id), "pr_number": pr.pr_number} for pr in prs]

        log.info("retro_scan.fetched", count=len(pr_list))
        return {**state, "pr_list": pr_list, "total": len(pr_list)}

    except Exception as exc:
        log.error("retro_scan.fetch_error", error=str(exc))
        return {**state, "pr_list": [], "total": 0, "error": str(exc)}


async def queue_scans_node(state: RetroScanState) -> RetroScanState:
    """Queue retro scans for each PR via the Arq worker."""
    from cryptography.fernet import Fernet
    from sqlalchemy import select

    from aegis.config import get_settings
    from aegis.db.models import Repository
    from aegis.db.session import get_session_factory
    from aegis.worker.graph_worker import enqueue_scan

    pr_list = state.get("pr_list", [])
    repo_db_id = state["repo_db_id"]
    queued: list[str] = []

    log.info("retro_scan.queue", prs=len(pr_list), repo_db_id=repo_db_id)

    if not pr_list:
        return {**state, "queued_jobs": [], "queued_count": 0}

    settings = get_settings()
    fernet = Fernet(settings.fernet_key.encode())

    session_factory = get_session_factory()
    async with session_factory() as session:
        result = await session.execute(select(Repository).where(Repository.id == repo_db_id))
        repo = result.scalar_one_or_none()

    if repo is None:
        log.error("retro_scan.repo_not_found", repo_db_id=repo_db_id)
        return {**state, "queued_jobs": [], "queued_count": 0, "error": "repository not found"}

    if not repo.token_encrypted:
        log.error("retro_scan.no_token", repo_db_id=repo_db_id)
        return {**state, "queued_jobs": [], "queued_count": 0, "error": "repository has no access token"}

    try:
        access_token = fernet.decrypt(repo.token_encrypted.encode()).decode()
    except Exception as exc:
        log.error("retro_scan.decrypt_failed", repo_db_id=repo_db_id, error=str(exc))
        return {**state, "queued_jobs": [], "queued_count": 0, "error": "failed to decrypt token"}

    slug = repo.slug
    provider = _provider_str(repo.provider)

    for pr in pr_list:
        try:
            scan_id = str(uuid.uuid4())
            job_id = await enqueue_scan(
                repo_id=str(repo_db_id),
                pr_id=str(pr["id"]),
                pr_number=int(pr["pr_number"]),
                scan_id=scan_id,
                repo_full_name=slug,
                access_token=access_token,
                head_sha="",
                provider=provider,
                pr_metadata={"number": pr["pr_number"], "retro": True},
                retro=True,
            )
            queued.append(job_id)
        except Exception as exc:
            log.warning("retro_scan.queue_error", pr=pr.get("pr_number"), error=str(exc))

    log.info("retro_scan.queued", count=len(queued))
    return {**state, "queued_jobs": queued, "queued_count": len(queued)}


async def summarize_node(state: RetroScanState) -> RetroScanState:
    """Summarize the retro scan job."""
    total = state.get("total", 0)
    queued_count = state.get("queued_count", 0)
    err = state.get("error")

    summary = {
        "total_prs": total,
        "queued_for_scan": queued_count,
        "status": "initiated" if not err else "failed",
    }
    if err:
        summary["error"] = err

    log.info("retro_scan.summary", **summary)
    return {**state, "summary": summary}


def build_retro_scan_subgraph() -> StateGraph:
    """Build and compile the retro scan subgraph."""
    builder = StateGraph(RetroScanState)

    builder.add_node("fetch_prs", fetch_prs_node)
    builder.add_node("queue_scans", queue_scans_node)
    builder.add_node("summarize", summarize_node)

    builder.set_entry_point("fetch_prs")
    builder.add_edge("fetch_prs", "queue_scans")
    builder.add_edge("queue_scans", "summarize")
    builder.add_edge("summarize", END)

    return builder.compile()


# Lazy-compiled instance
_retro_graph = None


def get_retro_graph():
    global _retro_graph
    if _retro_graph is None:
        _retro_graph = build_retro_scan_subgraph()
    return _retro_graph


async def run_retro_scan(repo_id: str, days_back: int = 30, limit: int = 50) -> dict:
    """Trigger a retro scan of historical PRs.

    Args:
        repo_id: Repository primary key (``repositories.id``) as string.
        days_back: How many days back to scan.
        limit: Maximum number of PRs to queue.

    Returns:
        Summary dict.
    """
    try:
        repo_db_id = int(repo_id)
    except ValueError:
        return {
            "total_prs": 0,
            "queued_for_scan": 0,
            "status": "failed",
            "error": "repo_id must be a numeric repository id",
        }

    graph = get_retro_graph()
    initial_state: RetroScanState = {
        "repo_db_id": repo_db_id,
        "days_back": days_back,
        "limit": limit,
        "pr_list": [],
        "total": 0,
        "queued_jobs": [],
        "queued_count": 0,
        "summary": {},
        "error": None,
    }

    result = await graph.ainvoke(initial_state)
    return result.get("summary", {})
