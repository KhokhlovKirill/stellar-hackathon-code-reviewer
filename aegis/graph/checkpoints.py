"""LangGraph PostgreSQL checkpointer setup (durable execution).

We deliberately default to ``MemorySaver`` for hackathon-style scans, where
durability across worker crashes is not required and webhook scans always
finish in a single Arq job. Setting ``ENABLE_GRAPH_CHECKPOINTING=true`` opts
in to PostgresSaver (durable across restarts) — the saver is a context
manager in modern LangGraph, so we open it once at process start and keep
the entered instance alive for the process lifetime.
"""

from __future__ import annotations

import atexit
import os

from aegis.config import settings
from aegis.observability.logging import get_logger

log = get_logger(__name__)

_checkpointer = None
_postgres_ctx = None  # holds the entered context-manager so we can close it on exit


def _postgres_conn_uri() -> str:
    """DSN for PostgresSaver (psycopg3) — strip SQLAlchemy driver suffix."""
    url = settings.database_sync_url.strip()
    for prefix in (
        "postgresql+psycopg2://",
        "postgresql+psycopg://",
        "postgres+psycopg2://",
    ):
        if url.startswith(prefix):
            return "postgresql://" + url.split("://", 1)[1]
    return url


def _build_postgres_saver():
    """Try to build a PostgresSaver. Returns ``None`` on any failure.

    Modern ``PostgresSaver.from_conn_string`` returns a context manager; we
    enter it once and register an ``atexit`` hook to close it.
    """
    global _postgres_ctx
    try:
        from langgraph.checkpoint.postgres import PostgresSaver
    except Exception as exc:
        log.warning("checkpointer.postgres_unavailable", reason=str(exc))
        return None

    try:
        candidate = PostgresSaver.from_conn_string(_postgres_conn_uri())

        # New API: returns a context manager (``__enter__`` returns the actual saver).
        if hasattr(candidate, "__enter__"):
            _postgres_ctx = candidate
            saver = candidate.__enter__()
            atexit.register(_close_postgres_ctx)
        else:
            # Older versions return the saver directly.
            saver = candidate

        # ``setup()`` creates the langgraph_checkpoints table if missing.
        if hasattr(saver, "setup"):
            saver.setup()

        log.info("checkpointer.ready", type="PostgresSaver")
        return saver
    except Exception as exc:
        log.warning("checkpointer.postgres_failed", reason=str(exc))
        # Best-effort: if we partially entered the context, leave the atexit
        # hook in place — it's safe to call __exit__ on a half-initialised CM.
        return None


def _close_postgres_ctx() -> None:
    global _postgres_ctx
    if _postgres_ctx is not None:
        try:
            _postgres_ctx.__exit__(None, None, None)
        except Exception:  # pragma: no cover — best effort
            pass
        finally:
            _postgres_ctx = None


def get_checkpointer():
    """Return a LangGraph checkpointer (singleton).

    Resolution order:
    1. If ``ENABLE_GRAPH_CHECKPOINTING=true``, try PostgresSaver.
    2. Otherwise (or on failure) fall back to in-memory ``MemorySaver``.
    """
    global _checkpointer
    if _checkpointer is not None:
        return _checkpointer

    use_postgres = os.environ.get("ENABLE_GRAPH_CHECKPOINTING", "").strip().lower() in (
        "1", "true", "yes", "on",
    )

    if use_postgres:
        saver = _build_postgres_saver()
        if saver is not None:
            _checkpointer = saver
            return _checkpointer

    from langgraph.checkpoint.memory import MemorySaver

    _checkpointer = MemorySaver()
    log.info("checkpointer.ready", type="MemorySaver")
    return _checkpointer
