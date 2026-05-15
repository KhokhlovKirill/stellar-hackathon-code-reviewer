"""Retro scan subgraph — re-scans historical PRs with updated rules."""

from __future__ import annotations

import asyncio
from typing import Any

from langgraph.graph import StateGraph, END

from aegis.graph.state import RetroScanState
from aegis.observability.logging import get_logger

log = get_logger(__name__)


async def fetch_prs_node(state: RetroScanState) -> RetroScanState:
    """Fetch historical PRs for retro scanning."""
    from aegis.db.session import get_session_factory
    from aegis.db.models import PullRequest
    from sqlalchemy import select

    repo_id = state.get("repo_id")
    days_back = state.get("days_back", 30)
    limit = state.get("limit", 50)

    log.info("retro_scan.fetch", repo_id=repo_id, days_back=days_back)

    try:
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)

        session_factory = get_session_factory()
        async with session_factory() as session:
            result = await session.execute(
                select(PullRequest)
                .where(
                    PullRequest.repo_id == repo_id,
                    PullRequest.created_at >= cutoff,
                )
                .order_by(PullRequest.created_at.desc())
                .limit(limit)
            )
            prs = result.scalars().all()
            pr_list = [
                {"id": str(pr.id), "pr_number": pr.pr_number, "head_sha": pr.head_sha}
                for pr in prs
            ]

        log.info("retro_scan.fetched", count=len(pr_list))
        return {**state, "pr_list": pr_list, "total": len(pr_list)}

    except Exception as exc:
        log.error("retro_scan.fetch_error", error=str(exc))
        return {**state, "pr_list": [], "total": 0, "error": str(exc)}


async def queue_scans_node(state: RetroScanState) -> RetroScanState:
    """Queue retro scans for each PR via the Arq worker."""
    from aegis.worker.graph_worker import enqueue_scan

    pr_list = state.get("pr_list", [])
    repo_id = state.get("repo_id")
    queued: list[str] = []

    log.info("retro_scan.queue", prs=len(pr_list))

    for pr in pr_list:
        try:
            job_id = await enqueue_scan(
                repo_id=repo_id,
                pr_id=pr.get("id"),
                pr_number=pr.get("pr_number"),
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

    summary = {
        "total_prs": total,
        "queued_for_scan": queued_count,
        "status": "initiated",
    }

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
        repo_id: Repository UUID string.
        days_back: How many days back to scan.
        limit: Maximum number of PRs to queue.

    Returns:
        Summary dict.
    """
    graph = get_retro_graph()
    initial_state: RetroScanState = {
        "repo_id": repo_id,
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
