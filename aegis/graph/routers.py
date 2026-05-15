"""Conditional routing functions for LangGraph edge transitions."""

from __future__ import annotations

from aegis.graph.state import SecurityGraphState


# ── Planner router ────────────────────────────────────────────────────────────

def route_after_planner(state: SecurityGraphState) -> str:
    """After planner: skip trivial PRs or proceed with analysis."""
    if state.get("next_action") == "skip":
        return "persist"
    return "filter"


# ── Deterministic scanner router ─────────────────────────────────────────────

def route_after_deterministic(state: SecurityGraphState) -> str:
    """After deterministic scanners: decide if LLM pass is needed."""
    if not state.get("requires_llm", True):
        return "risk"
    return "llm_agent_a"


# ── Risk router ───────────────────────────────────────────────────────────────

def route_after_risk(state: SecurityGraphState) -> str:
    """After risk scoring: route to HITL, blast_radius, or policy."""
    risk = state.get("risk_score", 0)
    if risk >= 80 or state.get("requires_human_review"):
        return "human_review"
    if risk >= 60:
        return "blast_radius"
    return "policy"


# ── Human review router ───────────────────────────────────────────────────────

def route_after_human_review(state: SecurityGraphState) -> str:
    """Dispatch based on the human decision recorded."""
    decision = state.get("human_decision", "")
    if decision == "rerun":
        return "llm_agent_a"
    if decision == "reject":
        return "policy"
    if decision == "escalate":
        return "policy"
    # approve / suppress — go straight to policy (will pass)
    return "policy"


# ── Policy router ─────────────────────────────────────────────────────────────

def route_after_policy(state: SecurityGraphState) -> str:
    """Decide if we create an autofix PR."""
    risk = state.get("risk_score", 0)
    if risk >= 60 and state.get("merged_findings"):
        return "autofix"
    return "render"
