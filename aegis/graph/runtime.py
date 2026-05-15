"""Graph execution runtime — invoke and resume helpers."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from aegis.config import settings
from aegis.graph.checkpoints import get_checkpointer
from aegis.observability.logging import get_logger
from aegis.observability.metrics import active_scans, langgraph_resume_total

log = get_logger(__name__)

_GRAPH = None  # lazy singleton


def _get_graph():
    global _GRAPH
    if _GRAPH is None:
        from aegis.graph.builder import build_security_graph
        _GRAPH = build_security_graph(checkpointer=get_checkpointer())
    return _GRAPH


async def execute_graph(initial_state: dict[str, Any]) -> dict[str, Any]:
    """Run a new security analysis graph and return final state.

    Wraps the synchronous LangGraph invoke() in a thread pool so it
    plays nicely with asyncio.
    """
    graph = _get_graph()
    scan_id: str = initial_state["scan_id"]
    config = {"configurable": {"thread_id": scan_id}, "recursion_limit": 64}

    log.info("graph.execute.start", scan_id=scan_id, pr=initial_state.get("pr_number"))
    active_scans.inc()

    try:
        result = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None, lambda: graph.invoke(initial_state, config=config)
            ),
            timeout=settings.max_graph_execution_seconds,
        )
        log.info(
            "graph.execute.done",
            scan_id=scan_id,
            status=result.get("status"),
            risk=result.get("risk_score"),
        )
        return result
    except asyncio.TimeoutError:
        log.error("graph.execute.timeout", scan_id=scan_id)
        return {**initial_state, "status": "error", "error_message": "Graph execution timed out"}
    except Exception as exc:
        log.exception("graph.execute.error", scan_id=scan_id, error=str(exc))
        return {**initial_state, "status": "error", "error_message": str(exc)}
    finally:
        active_scans.dec()


async def resume_graph(scan_id: str, update: dict[str, Any]) -> dict[str, Any]:
    """Resume an interrupted graph (HITL or crash recovery)."""
    graph = _get_graph()
    config = {"configurable": {"thread_id": scan_id}, "recursion_limit": 64}

    log.info("graph.resume.start", scan_id=scan_id, update_keys=list(update.keys()))
    langgraph_resume_total.inc()

    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: graph.invoke(update, config=config)
        )
        log.info("graph.resume.done", scan_id=scan_id, status=result.get("status"))
        return result
    except Exception as exc:
        log.exception("graph.resume.error", scan_id=scan_id, error=str(exc))
        return {"scan_id": scan_id, "status": "error", "error_message": str(exc)}


def get_graph_state(scan_id: str) -> dict[str, Any] | None:
    """Return the latest checkpointed state for a thread_id."""
    graph = _get_graph()
    config = {"configurable": {"thread_id": scan_id}}
    state = graph.get_state(config)
    if state is None:
        return None
    return dict(state.values)
