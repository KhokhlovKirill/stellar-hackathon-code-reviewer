"""Vector similarity search for the security knowledge base."""

from __future__ import annotations

from aegis.knowledge.embeddings import get_embedding
from aegis.db.session import get_session_factory
from aegis.observability.logging import get_logger

log = get_logger(__name__)


async def search_similar(query: str, top_k: int = 5) -> list[dict]:
    """Search the knowledge base for similar findings using cosine similarity.

    Args:
        query: Text query to search for.
        top_k: Number of results to return.

    Returns:
        List of similar finding dicts with similarity scores.
    """
    if not query:
        return []

    try:
        query_embedding = await get_embedding(query)
        return await _vector_search(query_embedding, top_k=top_k)
    except Exception as exc:
        log.warning("retrieval.search_error", error=str(exc))
        return []


async def _vector_search(embedding: list[float], top_k: int = 5) -> list[dict]:
    """Perform HNSW cosine similarity search via pgvector."""
    from aegis.db.models import KnowledgeBase
    from sqlalchemy import text
    from sqlalchemy.future import select

    session_factory = get_session_factory()
    async with session_factory() as session:
        # Use pgvector's <=> operator for cosine distance
        # Lower value = more similar
        result = await session.execute(
            text("""
                SELECT id, vuln_type, cwe, severity, description, fix_snippet, fingerprint,
                       1 - (embedding <=> :embedding::vector) AS similarity
                FROM knowledge_base
                WHERE embedding IS NOT NULL
                ORDER BY embedding <=> :embedding::vector
                LIMIT :top_k
            """),
            {"embedding": str(embedding), "top_k": top_k},
        )
        rows = result.fetchall()

        return [
            {
                "id": str(row.id),
                "vuln_type": row.vuln_type,
                "cwe": row.cwe,
                "severity": row.severity,
                "description": row.description,
                "fix_snippet": row.fix_snippet,
                "fingerprint": row.fingerprint,
                "similarity": float(row.similarity),
            }
            for row in rows
            if row.similarity > 0.5  # Filter low-similarity results
        ]


async def find_similar_findings_by_code(code_snippet: str, top_k: int = 3) -> list[dict]:
    """Find similar past findings given a code snippet.

    Args:
        code_snippet: Code to search for similar findings.
        top_k: Number of similar findings to return.

    Returns:
        List of similar findings.
    """
    return await search_similar(code_snippet, top_k=top_k)


async def find_fix_for_vulnerability(vuln_type: str, cwe: str | None = None) -> str | None:
    """Look up a fix suggestion for a known vulnerability type.

    Args:
        vuln_type: Vulnerability type string.
        cwe: Optional CWE identifier.

    Returns:
        Fix snippet string if found, else None.
    """
    query = f"{vuln_type} {cwe or ''}".strip()
    results = await search_similar(query, top_k=3)

    for r in results:
        if r.get("fix_snippet") and r.get("similarity", 0) > 0.7:
            return r["fix_snippet"]

    return None
