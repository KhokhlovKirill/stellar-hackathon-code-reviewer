"""Prometheus metrics definitions for the Aegis platform."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# ── Webhook ───────────────────────────────────────────────────────────────────

webhooks_received_total = Counter(
    "aegis_webhooks_received_total",
    "Total webhook events received",
    ["provider", "event_type"],
)

webhooks_invalid_signature_total = Counter(
    "aegis_webhooks_invalid_signature_total",
    "Webhook events with invalid HMAC signature",
    ["provider"],
)

# ── Graph / LangGraph ─────────────────────────────────────────────────────────

langgraph_node_duration_seconds = Histogram(
    "langgraph_node_duration_seconds",
    "LangGraph node execution duration in seconds",
    ["node_name"],
    buckets=[0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0],
)

langgraph_checkpoint_total = Counter(
    "langgraph_checkpoint_total",
    "Total LangGraph checkpoints saved",
)

langgraph_resume_total = Counter(
    "langgraph_resume_total",
    "Total LangGraph graph resumes after crash",
)

langgraph_interrupt_total = Counter(
    "langgraph_interrupt_total",
    "Total HITL interrupts triggered",
)

langgraph_retry_total = Counter(
    "langgraph_retry_total",
    "Total LangGraph node retries",
    ["node_name"],
)

langgraph_edge_transitions_total = Counter(
    "langgraph_edge_transitions_total",
    "Total edge transitions in LangGraph",
    ["from_node", "to_node"],
)

langgraph_agent_failures_total = Counter(
    "langgraph_agent_failures_total",
    "Total agent node failures",
    ["node_name"],
)

langgraph_parallel_tasks_total = Counter(
    "langgraph_parallel_tasks_total",
    "Total parallel tasks executed",
)

active_scans = Gauge(
    "aegis_active_scans",
    "Number of currently running PR scans",
)

# ── LLM ──────────────────────────────────────────────────────────────────────

llm_requests_total = Counter(
    "aegis_llm_requests_total",
    "Total LLM API requests",
    ["model", "agent"],
)

llm_tokens_used_total = Counter(
    "aegis_llm_tokens_used_total",
    "Total LLM tokens consumed",
    ["model", "type"],  # type: prompt/completion
)

llm_latency_seconds = Histogram(
    "aegis_llm_latency_seconds",
    "LLM response latency",
    ["model"],
    buckets=[1, 2, 5, 10, 20, 30, 60, 120],
)

llm_errors_total = Counter(
    "aegis_llm_errors_total",
    "Total LLM errors",
    ["model", "error_type"],
)

# ── Security findings ─────────────────────────────────────────────────────────

findings_total = Counter(
    "aegis_findings_total",
    "Total security findings",
    ["severity", "source"],
)

risk_score_histogram = Histogram(
    "aegis_risk_score",
    "Risk score distribution across PRs",
    buckets=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
)

prs_blocked_total = Counter(
    "aegis_prs_blocked_total",
    "Total PRs blocked due to high risk score",
)

# ── Scanner ───────────────────────────────────────────────────────────────────

scanner_duration_seconds = Histogram(
    "aegis_scanner_duration_seconds",
    "Security scanner execution duration",
    ["scanner"],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
)

scanner_errors_total = Counter(
    "aegis_scanner_errors_total",
    "Total scanner execution errors",
    ["scanner"],
)


def setup_metrics() -> None:
    """Called once at startup — metrics are registered via module-level instantiation."""
    pass  # registration happens automatically on import
