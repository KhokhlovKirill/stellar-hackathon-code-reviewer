"""Redis-backed session memory for ChatOps dialogs."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from aegis.observability.logging import get_logger

log = get_logger(__name__)

_SESSION_TTL_SECONDS = 3600 * 24  # 24 hours
_MAX_MESSAGES = 50  # max messages to keep per session


def _session_key(pr_id: str) -> str:
    return f"aegis:dialog:{pr_id}"


async def get_dialog_session(pr_id: str) -> dict:
    """Load dialog session for a PR from Redis.

    Returns:
        Session dict with 'messages' list and metadata.
    """
    try:
        import redis.asyncio as aioredis
        from aegis.config import get_settings

        settings = get_settings()
        client = aioredis.from_url(settings.redis_url)

        raw = await client.get(_session_key(pr_id))
        await client.aclose()

        if raw:
            return json.loads(raw)
    except Exception as exc:
        log.warning("dialog.load_error", pr_id=pr_id, error=str(exc))

    return {"pr_id": pr_id, "messages": [], "context": {}}


async def save_dialog_session(pr_id: str, session: dict) -> None:
    """Save dialog session to Redis with TTL."""
    try:
        import redis.asyncio as aioredis
        from aegis.config import get_settings

        settings = get_settings()
        client = aioredis.from_url(settings.redis_url)

        # Trim message history
        if len(session.get("messages", [])) > _MAX_MESSAGES:
            session["messages"] = session["messages"][-_MAX_MESSAGES:]

        await client.setex(
            _session_key(pr_id),
            _SESSION_TTL_SECONDS,
            json.dumps(session, default=str),
        )
        await client.aclose()
    except Exception as exc:
        log.warning("dialog.save_error", pr_id=pr_id, error=str(exc))


async def append_message(pr_id: str, role: str, content: str, metadata: dict | None = None) -> None:
    """Append a message to the dialog history.

    Args:
        pr_id: PR identifier.
        role: 'user' | 'bot'.
        content: Message content.
        metadata: Optional dict with extra info (command, user, etc.).
    """
    session = await get_dialog_session(pr_id)

    message: dict[str, Any] = {
        "role": role,
        "content": content,
    }
    if metadata:
        message["metadata"] = metadata

    from datetime import datetime, timezone
    message["timestamp"] = datetime.now(timezone.utc).isoformat()

    session["messages"].append(message)
    await save_dialog_session(pr_id, session)


async def get_recent_messages(pr_id: str, limit: int = 10) -> list[dict]:
    """Get the most recent messages for a PR dialog.

    Args:
        pr_id: PR identifier.
        limit: Number of recent messages to return.

    Returns:
        List of message dicts.
    """
    session = await get_dialog_session(pr_id)
    messages = session.get("messages", [])
    return messages[-limit:]


async def clear_dialog_session(pr_id: str) -> None:
    """Clear the dialog session for a PR."""
    try:
        import redis.asyncio as aioredis
        from aegis.config import get_settings

        settings = get_settings()
        client = aioredis.from_url(settings.redis_url)
        await client.delete(_session_key(pr_id))
        await client.aclose()
    except Exception as exc:
        log.warning("dialog.clear_error", pr_id=pr_id, error=str(exc))


async def update_context(pr_id: str, context_updates: dict) -> None:
    """Update the context dict in the dialog session.

    Args:
        pr_id: PR identifier.
        context_updates: Dict of context keys to update.
    """
    session = await get_dialog_session(pr_id)
    session.setdefault("context", {}).update(context_updates)
    await save_dialog_session(pr_id, session)
