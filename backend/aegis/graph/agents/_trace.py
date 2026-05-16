"""Shared decorator for graph nodes: per-node timing + error capture + trace.

Every agent in `aegis.graph.agents` is wrapped with `@traced("<name>")` so the
state's `trace` list grows with `{node, duration_ms, status}` rows in order,
and any unhandled exception becomes `state["error"]` instead of killing the
whole graph. Successful nodes return their own partial state update merged
with the trace; failed nodes return an error update.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any, cast

from aegis.graph.state import ScanGraphState
from aegis.obs import get_logger

log = get_logger("aegis.graph.node")

# Raw agent: returns a partial state update dict.
RawNodeFn = Callable[[ScanGraphState], Awaitable[dict[str, Any]]]
# Decorated agent (what LangGraph receives): returns a ScanGraphState.
WrappedNodeFn = Callable[[ScanGraphState], Awaitable[ScanGraphState]]


def traced(name: str) -> Callable[[RawNodeFn], WrappedNodeFn]:
    """Wrap a graph node with timing, structured logging and error capture."""

    def decorator(fn: RawNodeFn) -> WrappedNodeFn:
        @wraps(fn)
        async def wrapper(state: ScanGraphState) -> ScanGraphState:
            t0 = time.monotonic()
            try:
                update = await fn(state) or {}
                status = "ok"
                if update.get("error"):
                    status = "error"
                return _append_trace(state, update, name, t0, status)
            except Exception as exc:  # any node failure → set state.error, keep going
                log.exception("graph.node.exception", node=name, error=str(exc))
                return _append_trace(
                    state, {"error": f"{name}: {exc}"}, name, t0, "exception"
                )

        return wrapper

    return decorator


def _append_trace(
    state: ScanGraphState,
    update: dict[str, Any],
    name: str,
    t0: float,
    status: str,
) -> ScanGraphState:
    duration_ms = int((time.monotonic() - t0) * 1000)
    existing = list(state.get("trace") or [])
    existing.append({"node": name, "duration_ms": duration_ms, "status": status})
    out = dict(update)
    out["trace"] = existing
    log.info("graph.node.done", node=name, duration_ms=duration_ms, status=status)
    # `TypedDict(total=False)` permits any subset of keys; cast for the type
    # checker since LangGraph wants the state type back.
    return cast(ScanGraphState, out)
