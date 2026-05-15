"""Builds the Aegis LangGraph StateGraph with all 15 nodes."""

from __future__ import annotations

from langgraph.graph import StateGraph, END

from aegis.config import settings
from aegis.graph.state import SecurityGraphState
from aegis.graph.routers import (
    route_after_deterministic,
    route_after_human_review,
    route_after_planner,
    route_after_policy,
    route_after_risk,
)


def build_security_graph(checkpointer=None):
    """Construct and compile the security analysis StateGraph.

    Returns a compiled LangGraph. Agent nodes are async — call ``graph.ainvoke(...)``
    from asyncio code (see ``aegis.graph.runtime.execute_graph``).
    """
    # Import agents here to avoid circular imports at module load time
    from aegis.graph.agents.planner import planner_agent
    from aegis.graph.agents.filter_agent import filter_agent
    from aegis.graph.agents.context_agent import context_agent
    from aegis.graph.agents.deterministic_agent import deterministic_agent
    from aegis.graph.agents.llm_agent_a import llm_agent_a
    from aegis.graph.agents.llm_agent_b import llm_agent_b
    from aegis.graph.agents.judge_agent import judge_agent
    from aegis.graph.agents.risk_agent import risk_agent
    from aegis.graph.agents.blast_radius_agent import blast_radius_agent
    from aegis.graph.agents.policy_agent import policy_agent
    from aegis.graph.agents.autofix_agent import autofix_agent
    from aegis.graph.agents.render_agent import render_agent
    from aegis.graph.agents.publish_agent import publish_agent
    from aegis.graph.agents.persist_agent import persist_agent
    from aegis.graph.agents.human_review_agent import human_review_agent

    builder = StateGraph(SecurityGraphState)

    # ── Add nodes ─────────────────────────────────────────────────────────────
    builder.add_node("planner", planner_agent)
    builder.add_node("filter", filter_agent)
    builder.add_node("context", context_agent)
    builder.add_node("deterministic", deterministic_agent)
    builder.add_node("llm_agent_a", llm_agent_a)
    builder.add_node("llm_agent_b", llm_agent_b)
    builder.add_node("judge", judge_agent)
    builder.add_node("risk", risk_agent)
    builder.add_node("blast_radius", blast_radius_agent)
    builder.add_node("human_review", human_review_agent)
    builder.add_node("policy", policy_agent)
    builder.add_node("autofix", autofix_agent)
    builder.add_node("render", render_agent)
    builder.add_node("publish", publish_agent)
    builder.add_node("persist", persist_agent)

    # ── Entry point ───────────────────────────────────────────────────────────
    builder.set_entry_point("planner")

    # ── Conditional edges ─────────────────────────────────────────────────────
    builder.add_conditional_edges(
        "planner",
        route_after_planner,
        {"filter": "filter", "persist": "persist"},
    )

    # Linear edges
    builder.add_edge("filter", "context")
    builder.add_edge("context", "deterministic")

    builder.add_conditional_edges(
        "deterministic",
        route_after_deterministic,
        {"llm_agent_a": "llm_agent_a", "risk": "risk"},
    )

    builder.add_edge("llm_agent_a", "llm_agent_b")
    builder.add_edge("llm_agent_b", "judge")
    builder.add_edge("judge", "risk")

    builder.add_conditional_edges(
        "risk",
        route_after_risk,
        {"human_review": "human_review", "blast_radius": "blast_radius", "policy": "policy"},
    )

    builder.add_edge("blast_radius", "policy")

    builder.add_conditional_edges(
        "human_review",
        route_after_human_review,
        {"llm_agent_a": "llm_agent_a", "policy": "policy"},
    )

    builder.add_conditional_edges(
        "policy",
        route_after_policy,
        {"autofix": "autofix", "render": "render"},
    )

    builder.add_edge("autofix", "render")
    builder.add_edge("render", "publish")
    builder.add_edge("publish", "persist")
    builder.add_edge("persist", END)

    # Static interrupt_before causes ainvoke to stop until resume_graph() — without resume,
    # scans stay "running" forever. Opt-in via ENABLE_GRAPH_INTERRUPT_HUMAN_REVIEW.
    interrupt_before = (
        ["human_review"] if settings.enable_graph_interrupt_human_review else []
    )
    return builder.compile(checkpointer=checkpointer, interrupt_before=interrupt_before)
