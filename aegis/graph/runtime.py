"""Graph execution runtime — invoke and resume helpers."""

from __future__ import annotations

import asyncio
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


def _strip_interrupt(result: dict[str, Any]) -> dict[str, Any]:
    """Pop LangGraph's ``__interrupt__`` marker and tag status."""
    out = {k: v for k, v in result.items() if k != "__interrupt__"}
    out.setdefault("human_review_pending", True)
    out["status"] = "interrupted"
    return out


async def execute_graph(initial_state: dict[str, Any]) -> dict[str, Any]:
    """Run a new security analysis graph and return final state.

    Uses LangGraph ``ainvoke`` because all agent nodes are async coroutines;
    synchronous ``invoke`` cannot run them. Wraps execution in
    ``asyncio.wait_for`` with ``settings.max_graph_execution_seconds`` so a
    runaway scan can never block a worker slot indefinitely.
    """
    graph = _get_graph()
    scan_id: str = initial_state["scan_id"]
    config = {"configurable": {"thread_id": scan_id}, "recursion_limit": 64}

    log.info("graph.execute.start", scan_id=scan_id, pr=initial_state.get("pr_number"))
    active_scans.inc()

    try:
        result = await asyncio.wait_for(
            graph.ainvoke(initial_state, config=config),
            timeout=settings.max_graph_execution_seconds,
        )
        if isinstance(result, dict) and result.get("__interrupt__"):
            log.info(
                "graph.execute.interrupted",
                scan_id=scan_id,
                interrupt=repr(result.get("__interrupt__"))[:500],
            )
            return _strip_interrupt(result)

        if isinstance(result, dict):
            log.info(
                "graph.execute.done",
                scan_id=scan_id,
                status=result.get("status"),
                risk=result.get("risk_score"),
            )
            return result
        return {"status": "error", "error_message": "Graph returned a non-dict result"}
    except asyncio.TimeoutError:
        log.error("graph.execute.timeout", scan_id=scan_id)
        return {**initial_state, "status": "error", "error_message": "Graph execution timed out"}
    except Exception as exc:
        log.exception("graph.execute.error", scan_id=scan_id, error=str(exc))
        return {**initial_state, "status": "error", "error_message": str(exc)}
    finally:
        active_scans.dec()


async def resume_graph(scan_id: str, update: dict[str, Any]) -> dict[str, Any]:
    """Resume an interrupted graph (HITL or crash recovery).

    Accepts ``scan_id`` as either a positional or keyword argument; legacy
    callers used ``thread_id=...`` so we transparently treat both names the
    same way upstream.
    """
    graph = _get_graph()
    config = {"configurable": {"thread_id": str(scan_id)}, "recursion_limit": 64}

    log.info("graph.resume.start", scan_id=scan_id, update_keys=list((update or {}).keys()))
    langgraph_resume_total.inc()

    try:
        # Try the modern LangGraph resume API (Command(resume=...)). Falls back
        # to passing the update dict directly when the runtime version doesn't
        # provide Command (e.g. langgraph<0.2).
        payload: Any
        try:
            from langgraph.types import Command  # type: ignore[attr-defined]

            payload = Command(resume=update or {})
        except Exception:
            payload = update or {}

        result = await asyncio.wait_for(
            graph.ainvoke(payload, config=config),
            timeout=settings.max_graph_execution_seconds,
        )

        if isinstance(result, dict) and result.get("__interrupt__"):
            log.info("graph.resume.interrupted", scan_id=scan_id)
            return _strip_interrupt(result)

        if isinstance(result, dict):
            log.info("graph.resume.done", scan_id=scan_id, status=result.get("status"))
            return result
        return {"scan_id": scan_id, "status": "error", "error_message": "Non-dict result"}
    except Exception as exc:
        log.exception("graph.resume.error", scan_id=scan_id, error=str(exc))
        return {"scan_id": scan_id, "status": "error", "error_message": str(exc)}


def get_graph_state(scan_id: str) -> dict[str, Any] | None:
    """Return the latest checkpointed state for a thread_id."""
    graph = _get_graph()
    config = {"configurable": {"thread_id": scan_id}}
    try:
        state = graph.get_state(config)
    except Exception as exc:
        log.warning("graph.get_state_error", scan_id=scan_id, error=str(exc))
        return None
    if state is None:
        return None
    return dict(state.values)
