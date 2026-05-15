"""Single shared async Redis client (idempotency, cache, queue helpers)."""

from __future__ import annotations

import functools
from typing import cast

import redis.asyncio as aioredis

from aegis.config import get_settings


@functools.lru_cache(maxsize=1)
def redis() -> aioredis.Redis:
    return cast(
        aioredis.Redis,
        aioredis.from_url(  # type: ignore[no-untyped-call]
            get_settings().redis_url, decode_responses=True
        ),
    )
