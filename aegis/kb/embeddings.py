"""Embedding client — LM Studio OpenAI-compatible /v1/embeddings (nomic-embed).

Graceful by design: any failure (model not loaded, LM Studio down, timeout)
returns None so the KB stage degrades to a no-op instead of failing the scan.
"""

from __future__ import annotations

import math

import httpx

from aegis.config import get_config, get_settings
from aegis.obs import get_logger

log = get_logger("aegis.kb.embeddings")


def _embed_text(finding_title: str, snippet: str, cwe: str | None) -> str:
    """Compact, stable representation of a finding for embedding."""
    return f"[{cwe or 'n/a'}] {finding_title}\n{snippet}".strip()[:4000]


async def embed(finding_title: str, snippet: str, cwe: str | None) -> list[float] | None:
    settings = get_settings()
    timeout = get_config().kb.embed_timeout_seconds
    text = _embed_text(finding_title, snippet, cwe)
    if not text:
        return None
    url = settings.lmstudio_base_url.rstrip("/") + "/embeddings"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(
                url,
                json={"model": settings.lmstudio_embed_model, "input": text},
            )
        if r.status_code >= 400:
            log.warning("kb.embed_http_error", code=r.status_code, body=r.text[:200])
            return None
        data = r.json()
        vec = data["data"][0]["embedding"]
        if not isinstance(vec, list) or not vec:
            return None
        return [float(x) for x in vec]
    except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
        log.warning("kb.embed_failed", error=str(exc))
        return None


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity. Returns 0.0 for mismatched/empty/zero vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = math.fsum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(math.fsum(x * x for x in a))
    nb = math.sqrt(math.fsum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)
