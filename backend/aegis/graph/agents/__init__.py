"""LangGraph node implementations.

Each module exports a single async callable that receives a `ScanGraphState`
and returns a partial update. Bodies are deliberately thin: they delegate to
the existing `aegis.pipeline.simple_scan` helpers so the graph stays a pure
orchestration layer and there is exactly one implementation of the scan
logic in the codebase.
"""

from aegis.graph.agents.deterministic import deterministic_agent
from aegis.graph.agents.fetch import fetch_diff_agent, fetch_pr_agent
from aegis.graph.agents.filter import filter_agent
from aegis.graph.agents.finalize import finalize_agent
from aegis.graph.agents.llm import llm_agent
from aegis.graph.agents.parse import parse_agent
from aegis.graph.agents.review import review_agent

__all__ = [
    "deterministic_agent",
    "fetch_diff_agent",
    "fetch_pr_agent",
    "filter_agent",
    "finalize_agent",
    "llm_agent",
    "parse_agent",
    "review_agent",
]
