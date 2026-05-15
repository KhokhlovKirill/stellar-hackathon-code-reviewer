"""Webhook idempotency (criterion C1: replay must not produce a second scan).

Key = WebhookEvent.dedupe_key() (provider+delivery+repo+pr+head_sha). SET NX EX:
the first webhook for a (pr, head_sha) wins; redeliveries / duplicate pushes on the
same commit short-circuit. A new commit (new head_sha) is a new key -> new scan.
"""

from __future__ import annotations

from aegis.config import get_config
from aegis.redispool import redis


async def claim(dedupe_key: str) -> bool:
    """True if this is the first time we see this event (caller should process).
    False if it's a duplicate/replay (caller should ack and skip)."""
    ttl = get_config().service.idempotency_ttl_seconds
    ok = await redis().set(f"aegis:idem:{dedupe_key}", "1", nx=True, ex=ttl)
    return bool(ok)


async def release(dedupe_key: str) -> None:
    """Drop the claim so a failed scan can be retried by a redelivery."""
    await redis().delete(f"aegis:idem:{dedupe_key}")
