"""Embedding generation for security findings and code snippets."""

from __future__ import annotations

import asyncio
from typing import Sequence

from aegis.observability.logging import get_logger

log = get_logger(__name__)

_EMBEDDING_DIM = 1536  # OpenAI text-embedding-3-small / ada-002 dimension
_BATCH_SIZE = 32


async def get_embeddings(texts: list[str]) -> list[list[float]]:
    """Generate embeddings for a list of texts.

    Uses OpenAI text-embedding-3-small if available, otherwise falls back
    to a local sentence-transformer model.

    Args:
        texts: List of text strings to embed.

    Returns:
        List of embedding vectors, same length as input.
    """
    if not texts:
        return []

    from aegis.config import get_settings
    settings = get_settings()

    # OpenRouter keys are not valid on api.openai.com — use local embeddings unless OPENAI_API_KEY is set.
    openai_key = settings.openai_api_key or None

    if openai_key:
        return await _get_openai_embeddings(texts, openai_key, settings)
    else:
        return await _get_local_embeddings(texts)


async def get_embedding(text: str) -> list[float]:
    """Get embedding for a single text."""
    results = await get_embeddings([text])
    return results[0] if results else [0.0] * _EMBEDDING_DIM


async def _get_openai_embeddings(
    texts: list[str],
    api_key: str,
    settings,
) -> list[list[float]]:
    """Generate embeddings using OpenAI API."""
    import httpx

    base_url = "https://api.openai.com/v1"
    model = "text-embedding-3-small"

    all_embeddings: list[list[float]] = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Process in batches
        for i in range(0, len(texts), _BATCH_SIZE):
            batch = texts[i : i + _BATCH_SIZE]
            # Truncate texts to avoid token limit
            batch = [t[:8000] for t in batch]

            try:
                response = await client.post(
                    f"{base_url}/embeddings",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={"model": model, "input": batch},
                )
                response.raise_for_status()
                data = response.json()

                # Sort by index to preserve order
                sorted_data = sorted(data["data"], key=lambda x: x["index"])
                all_embeddings.extend([item["embedding"] for item in sorted_data])

            except Exception as exc:
                log.warning("embeddings.openai_error", error=str(exc), batch_size=len(batch))
                # Return zero vectors for failed batch
                all_embeddings.extend([[0.0] * _EMBEDDING_DIM] * len(batch))

    return all_embeddings


async def _get_local_embeddings(texts: list[str]) -> list[list[float]]:
    """Fallback: generate embeddings using a local model via sentence-transformers."""
    try:
        from sentence_transformers import SentenceTransformer

        def _embed_sync():
            model = SentenceTransformer("all-MiniLM-L6-v2")
            return model.encode(texts).tolist()

        loop = asyncio.get_event_loop()
        embeddings = await loop.run_in_executor(None, _embed_sync)
        # Pad to 1536 if needed for pgvector compatibility
        dim = len(embeddings[0]) if embeddings else 384
        if dim < _EMBEDDING_DIM:
            pad_size = _EMBEDDING_DIM - dim
            embeddings = [e + [0.0] * pad_size for e in embeddings]
        return embeddings
    except ImportError:
        log.warning("embeddings.local_not_available", fallback="zero_vectors")
        return [[0.0] * _EMBEDDING_DIM] * len(texts)


def build_finding_text(finding: dict) -> str:
    """Build a text representation of a finding for embedding."""
    parts = []
    if finding.get("vuln_type"):
        parts.append(f"Vulnerability: {finding['vuln_type']}")
    if finding.get("cwe"):
        parts.append(f"CWE: {finding['cwe']}")
    if finding.get("description"):
        parts.append(f"Description: {finding['description']}")
    if finding.get("file_path"):
        parts.append(f"File: {finding['file_path']}")
    if finding.get("fix_snippet"):
        parts.append(f"Fix: {finding['fix_snippet'][:500]}")
    return "\n".join(parts)
