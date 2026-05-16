"""LangGraph orchestration layer over the existing Aegis pipeline.

The current `aegis.pipeline.simple_scan.run_simple_scan` already implements
the full pull-mode scanner. This package lifts each of its stages
(parse URL → fetch PR → fetch diff → filter files → deterministic scan →
LLM ensemble → review → finalize) into a typed LangGraph `StateGraph` node
so the same logic gains:

  * a declarative DAG (easy to extend with new stages or parallel branches),
  * per-node execution traces and durations for observability,
  * checkpointing for crash recovery / human-in-the-loop pauses,
  * a stable seam to plug in additional agents (autofix, policy, publish).

The existing `run_simple_scan` path stays the production default. The graph
path is gated by the `AEGIS_USE_LANGGRAPH=1` env flag and reachable directly
via `aegis.graph.runner.run_graph_scan(...)`, which returns the same
`SimpleScanResult` shape so all existing API endpoints work unchanged.
"""

from aegis.graph.runner import run_graph_scan

__all__ = ["run_graph_scan"]
