"""Prometheus metrics. One registry, exposed at GET /metrics.

Names match docs/09; the analytics dashboards (deploy/grafana) query these.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

REGISTRY = CollectorRegistry()


class _Metrics:
    def __init__(self) -> None:
        r = REGISTRY
        self.scans_total = Counter(
            "aegis_scans_total", "Scans run", ["provider", "result"], registry=r
        )
        self.scan_duration = Histogram(
            "aegis_scan_duration_seconds", "End-to-end scan duration",
            buckets=(1, 2, 5, 10, 20, 40, 80, 160, 320), registry=r,
        )
        self.findings_total = Counter(
            "aegis_findings_total", "Findings emitted",
            ["severity", "cwe", "source"], registry=r,
        )
        self.llm_tokens_total = Counter(
            "aegis_llm_tokens_total", "LLM tokens", ["tier", "kind"], registry=r
        )
        self.llm_cost_usd_total = Counter(
            "aegis_llm_cost_usd_total", "LLM cost (USD)", ["tier"], registry=r
        )
        self.llm_latency = Histogram(
            "aegis_llm_latency_seconds", "LLM call latency", ["tier"],
            buckets=(0.5, 1, 2, 5, 10, 20, 40, 80, 120), registry=r,
        )
        self.llm_tier_down = Gauge(
            "aegis_llm_tier_down", "1 if tier currently unreachable", ["tier"], registry=r
        )
        self.llm_fallback_total = Counter(
            "aegis_llm_fallback_total", "Tier fallbacks", ["from_tier", "to_tier"], registry=r
        )
        self.vcs_calls_total = Counter(
            "aegis_vcs_calls_total", "VCS API calls", ["provider", "op", "code"], registry=r
        )
        self.filter_skipped_total = Counter(
            "aegis_filter_skipped_total", "Files filtered out", ["reason"], registry=r
        )
        self.tokens_saved_total = Counter(
            "aegis_tokens_saved_total", "Tokens saved vs full-repo (est)", registry=r
        )
        self.fp_feedback_total = Counter(
            "aegis_fp_feedback_total", "Author feedback on bot comments", ["kind"], registry=r
        )
        self.queue_depth = Gauge("aegis_queue_depth", "Pending scan jobs", registry=r)
        self.dialog_turns_total = Counter(
            "aegis_dialog_turns_total", "Dialog turns answered", registry=r
        )
        self.webhooks_total = Counter(
            "aegis_webhooks_total", "Webhooks received",
            ["provider", "kind", "sig_ok"], registry=r,
        )

    def render(self) -> bytes:
        return generate_latest(REGISTRY)


metrics = _Metrics()
