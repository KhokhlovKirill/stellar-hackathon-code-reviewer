"""Structured JSON logging with mandatory secret redaction.

Every log line is JSON, correlation-keyed by scan_id. A redaction processor runs
*before* serialization so tokens / keys / secret-finding values never reach disk —
this is a hard requirement (docs/10), enforced and tested (eval/load grep).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, MutableMapping
from typing import Any, cast

import structlog

# Patterns mirror the deterministic secret detector so anything we would flag in
# user code is also scrubbed from our own logs.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(authorization\s*:\s*)(bearer\s+)?[A-Za-z0-9._\-]{8,}"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{4,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),                # GitHub tokens
    re.compile(r"glpat-[A-Za-z0-9_\-]{15,}"),                 # GitLab PAT
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),              # Slack
    re.compile(r"AKIA[0-9A-Z]{16}"),                          # AWS access key id
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                       # OpenAI-style
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
]
_REDACTED = "«redacted»"
_SENSITIVE_KEYS = {
    "token", "secret", "password", "api_key", "vault_key", "authorization",
    "ciphertext", "openrouter_api_key", "webhook_secret", "raw_body",
}


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        out = value
        for pat in _SECRET_PATTERNS:
            out = pat.sub(_REDACTED, out)
        return out
    if isinstance(value, dict):
        return {
            k: (_REDACTED if k.lower() in _SENSITIVE_KEYS else _scrub(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return type(value)(_scrub(v) for v in value)
    return value


def _redaction_processor(
    _: Any, __: str, event_dict: MutableMapping[str, Any]
) -> Mapping[str, Any]:
    return {k: _scrub(v) for k, v in event_dict.items()}


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _redaction_processor,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "aegis") -> structlog.stdlib.BoundLogger:
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))


def bind_scan(**kwargs: Any) -> None:
    """Bind scan-correlation context (scan_id, repo, pr, head_sha, provider, stage)."""
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_scan() -> None:
    structlog.contextvars.clear_contextvars()
