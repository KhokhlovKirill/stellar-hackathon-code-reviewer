"""LangGraph PostgreSQL checkpointer setup (durable execution)."""

from __future__ import annotations

from aegis.config import settings
from aegis.observability.logging import get_logger

log = get_logger(__name__)

_checkpointer = None


def get_checkpointer():
    """Return a LangGraph PostgresSaver (sync-compatible shim).

    LangGraph >= 0.2 ships `langgraph.checkpoint.postgres.PostgresSaver`
    that accepts a standard psycopg2/psycopg connection string.
    """
    global _checkpointer
    if _checkpointer is not None:
        return _checkpointer

    try:
        from langgraph.checkpoint.postgres import PostgresSaver

        _checkpointer = PostgresSaver.from_conn_string(settings.database_sync_url)
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
