"""StateGraph construction.

Topology (compiled once, reused across scans):

    parse ─► fetch_pr ─► fetch_diff ─► filter ─► deterministic ─► llm ─► review ─► finalize ─► END
       │         │           │           │
       └─error──►│  ┌─error──┤   error ──┤
                 │  │        │           │
                 ▼  ▼        ▼           ▼
              finalize    finalize    finalize    (any node error → finalize)

The filter node can also short-circuit straight to `review` when the diff
contains no security-relevant files (skip deterministic + LLM).
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, StateGraph

from aegis.graph.routers import (
    route_after_fetch_diff,
    route_after_fetch_pr,
    route_after_filter,
    route_after_parse,
)
from aegis.graph.state import ScanGraphState

_compiled: Any = None


def build_security_graph(checkpointer: Any | None = None) -> Any:
    """Construct and compile the security-review StateGraph (singleton).

    The compiled graph is cached, so the first call pays the wiring cost and
    subsequent calls are O(1). Pass `checkpointer=None` to use the default
    (Postgres if available, else memory).
    """
    global _compiled
    if _compiled is not None and checkpointer is None:
        return _compiled

    # Late imports to avoid loading langgraph at module-import time for code
    # paths (e.g. simple_scan) that don't use the graph.
    from aegis.graph.agents import (
        deterministic_agent,
        fetch_diff_agent,
        fetch_pr_agent,
        filter_agent,
        finalize_agent,
        llm_agent,
        parse_agent,
        review_agent,
    )

    if checkpointer is None:
        from aegis.graph.checkpoints import get_checkpointer

        checkpointer = get_checkpointer()

    g = StateGraph(ScanGraphState)

    g.add_node("parse", parse_agent)  # type: ignore[call-overload]
    g.add_node("fetch_pr", fetch_pr_agent)  # type: ignore[call-overload]
    g.add_node("fetch_diff", fetch_diff_agent)  # type: ignore[call-overload]
    g.add_node("filter", filter_agent)  # type: ignore[call-overload]
    g.add_node("deterministic", deterministic_agent)  # type: ignore[call-overload]
    g.add_node("llm", llm_agent)  # type: ignore[call-overload]
    g.add_node("review", review_agent)  # type: ignore[call-overload]
    g.add_node("finalize", finalize_agent)  # type: ignore[call-overload]

    g.set_entry_point("parse")

    g.add_conditional_edges(
        "parse", route_after_parse, {"fetch_pr": "fetch_pr", "finalize": "finalize"}
    )
    g.add_conditional_edges(
        "fetch_pr",
        route_after_fetch_pr,
        {"fetch_diff": "fetch_diff", "finalize": "finalize"},
    )
    g.add_conditional_edges(
        "fetch_diff",
        route_after_fetch_diff,
        {"filter": "filter", "finalize": "finalize"},
    )
    g.add_conditional_edges(
        "filter",
        route_after_filter,
        {
            "deterministic": "deterministic",
            "review": "review",
            "finalize": "finalize",
        },
    )

    g.add_edge("deterministic", "llm")
    g.add_edge("llm", "review")
    g.add_edge("review", "finalize")
    g.add_edge("finalize", END)

    compiled = g.compile(checkpointer=checkpointer)
    _compiled = compiled
    return compiled
