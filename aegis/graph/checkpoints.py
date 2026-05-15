"""LangGraph PostgreSQL checkpointer setup (durable execution)."""

from __future__ import annotations

from aegis.config import settings
from aegis.observability.logging import get_logger

log = get_logger(__name__)

_checkpointer = None


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


def get_checkpointer():
    """Return a LangGraph PostgresSaver (sync-compatible shim).

    LangGraph >= 0.2 ships `langgraph.checkpoint.postgres.PostgresSaver`
    Requires package ``langgraph-checkpoint-postgres`` (psycopg3).
    """
    global _checkpointer
    if _checkpointer is not None:
        return _checkpointer

    try:
        from langgraph.checkpoint.postgres import PostgresSaver

        _checkpointer = PostgresSaver.from_conn_string(_postgres_conn_uri())
        _checkpointer.setup()  # creates langgraph_checkpoints table if not present
        log.info("checkpointer.ready", type="PostgresSaver")
    except Exception as exc:
        log.warning(
            "checkpointer.fallback_memory",
            reason=str(exc),
        )
        from langgraph.checkpoint.memory import MemorySaver
        _checkpointer = MemorySaver()

    return _checkpointer
