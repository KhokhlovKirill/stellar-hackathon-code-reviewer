"""Redis-backed LLM response cache keyed by content hash.

Key: sha1(model + role + sorted(messages_content))
TTL: 1 hour (same head_sha → same diff → same response valid)

Only caches successful completions. Cache misses are transparent — the caller
just gets None and proceeds to the real LLM call.
"""

from __future__ import annotations

import hashlib
import json

from aegis.llm.base import ChatMessage, LLMCompletion, LLMUsage
from aegis.obs import get_logger
from aegis.redispool import redis

log = get_logger("aegis.llm.cache")

_TTL = 3600  # 1 hour
_PREFIX = "aegis:llm:cache:"


def _cache_key(model: str, role: str, messages: list[ChatMessage]) -> str:
    content = json.dumps({"model": model, "role": role, "msgs": messages}, sort_keys=True)
    return _PREFIX + hashlib.sha1(content.encode()).hexdigest()  # noqa: S324


async def get_cached(
    model: str, role: str, messages: list[ChatMessage]
) -> LLMCompletion | None:
    key = _cache_key(model, role, messages)
    try:
        raw = await redis().get(key)
        if raw is None:
            return None
        data = json.loads(raw)
        log.info("llm.cache_hit", role=role, model=model, key=key[-8:])
        return LLMCompletion(
            tier=data["tier"],
            model=data["model"],
            role=data["role"],
            content=data["content"],
            usage=LLMUsage(
                prompt_tokens=data["usage"]["prompt_tokens"],
                completion_tokens=data["usage"]["completion_tokens"],
                cost_usd=0.0,  # cached — no cost
            ),
            latency_ms=0,
            degraded=False,
        )
    except Exception as exc:
        log.warning("llm.cache_get_error", error=str(exc))
        return None


async def set_cached(
    model: str, role: str, messages: list[ChatMessage], completion: LLMCompletion
) -> None:
    key = _cache_key(model, role, messages)
    data = {
        "tier": completion.tier,
        "model": completion.model,
        "role": completion.role,
        "content": completion.content,
        "usage": {
            "prompt_tokens": completion.usage.prompt_tokens,
            "completion_tokens": completion.usage.completion_tokens,
        },
    }
    try:
        await redis().set(key, json.dumps(data), ex=_TTL)
    except Exception as exc:
        log.warning("llm.cache_set_error", error=str(exc))
