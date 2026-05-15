"""Observability: structured logging (with secret redaction) and Prometheus metrics."""

from aegis.obs.logging import bind_scan, get_logger, setup_logging
from aegis.obs.metrics import metrics

__all__ = ["bind_scan", "get_logger", "metrics", "setup_logging"]
