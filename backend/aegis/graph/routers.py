"""Conditional edge functions for the security review graph."""

from __future__ import annotations

from aegis.graph.state import ScanGraphState


def route_after_parse(state: ScanGraphState) -> str:
    """If URL parsing failed, jump straight to finalize."""
    return "finalize" if state.get("error") else "fetch_pr"


def route_after_fetch_pr(state: ScanGraphState) -> str:
    return "finalize" if state.get("error") else "fetch_diff"


def route_after_fetch_diff(state: ScanGraphState) -> str:
    return "finalize" if state.get("error") else "filter"


def route_after_filter(state: ScanGraphState) -> str:
    """No security-relevant files → skip deterministic + LLM, go straight to review."""
    if state.get("error"):
        return "finalize"
    return "review" if state.get("skip_llm") else "deterministic"
