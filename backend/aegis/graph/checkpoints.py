"""LangGraph checkpointer factory.

PostgresSaver is used when the optional `langgraph-checkpoint-postgres`
package is installed and a sync DB URL is reachable; otherwise we fall back
to the in-memory saver. Scan graphs are short-lived enough that the memory
saver is a fine production default — checkpoints exist to support future
human-in-the-loop pauses and crash recovery.
"""

from __future__ import annotations

from typing import Any

from aegis.obs import get_logger

log = get_logger("aegis.graph.checkpoints")

_checkpointer: Any = None


def get_checkpointer() -> Any:
    """Return a process-singleton checkpointer (Postgres if available, else memory)."""
    global _checkpointer
    if _checkpointer is not None:
        return _checkpointer

    try:
        from langgraph.checkpoint.postgres import PostgresSaver

        from aegis.config import get_settings

        settings = get_settings()
        sync_url = getattr(settings, "database_sync_url", None) or _async_to_sync(
            getattr(settings, "database_url", "")
        )
        if sync_url:
            _checkpointer = PostgresSaver.from_conn_string(sync_url)
            _checkpointer.setup()
            log.info("graph.checkpointer.ready", backend="postgres")
            return _checkpointer
    except Exception as exc:  # ModuleNotFoundError, connect error, etc.
        log.info("graph.checkpointer.fallback_memory", reason=str(exc))

    from langgraph.checkpoint.memory import MemorySaver

    _checkpointer = MemorySaver()
    log.info("graph.checkpointer.ready", backend="memory")
    return _checkpointer


def _async_to_sync(url: str) -> str:
    """Best-effort conversion of an asyncpg URL to a psycopg-compatible one."""
    if not url:
        return ""
    return (
        url.replace("postgresql+asyncpg://", "postgresql://")
        .replace("postgres+asyncpg://", "postgresql://")
    )
