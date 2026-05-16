"""Async execution wrapper around the compiled StateGraph."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import cast

from aegis.graph.builder import build_security_graph
from aegis.graph.state import ScanGraphState
from aegis.obs import get_logger

log = get_logger("aegis.graph.runtime")


async def execute_graph(initial: ScanGraphState) -> ScanGraphState:
    """Run the security-review graph and return the final merged state.

    A `thread_id` is generated per call so each scan is checkpointed
    independently. `ainvoke` runs the graph asynchronously end-to-end.
    """
    graph = build_security_graph()
    thread_id = uuid.uuid4().hex
    config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 32}

    state: ScanGraphState = cast(ScanGraphState, dict(initial))  # shallow copy
    state.setdefault("started_at", datetime.now(UTC).isoformat())
    state.setdefault("trace", [])

    log.info("graph.execute.start", thread=thread_id, url=state.get("url"))
    try:
        final: ScanGraphState = cast(
            ScanGraphState, await graph.ainvoke(state, config=config)
        )
    except Exception as exc:
        log.exception("graph.execute.crash", error=str(exc))
        return {
            **state,
            "error": f"graph execution crashed: {exc}",
            "status": "error",
            "finished_at": datetime.now(UTC).isoformat(),
        }

    log.info(
        "graph.execute.done",
        thread=thread_id,
        status=final.get("status"),
        nodes=len(final.get("trace") or []),
    )
    return final
