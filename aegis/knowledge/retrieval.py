"""Vector similarity search for the security knowledge base."""

from __future__ import annotations

from aegis.db.session import get_session_factory
from aegis.knowledge.embeddings import get_embedding
from aegis.observability.logging import get_logger

log = get_logger(__name__)


async def search_similar(
    query: str,
    top_k: int = 5,
    repo_id: int | str | None = None,
    min_similarity: float = 0.5,
) -> list[dict]:
    """Search the knowledge base for similar findings using cosine similarity.

    Args:
        query: Text query to search for.
        top_k: Number of results to return.
        repo_id: Optional repository PK to filter by (results bias toward this repo).
        min_similarity: Minimum cosine similarity to include in results.

    Returns:
        List of similar finding dicts with similarity scores.
    """
    if not query:
        return []

    try:
        query_embedding = await get_embedding(query)
        return await _vector_search(
            query_embedding,
            top_k=top_k,
            repo_id=repo_id,
            min_similarity=min_similarity,
        )
    except Exception as exc:
        log.warning("retrieval.search_error", error=str(exc))
        return []


async def search_similar_by_text(
    query: str,
    top_k: int = 5,
    repo_id: int | str | None = None,
) -> list[dict]:
    """Compatibility alias used by ``code_rag``.

    Same as :func:`search_similar` but with a shorter, intent-revealing name.
    """
    return await search_similar(query=query, top_k=top_k, repo_id=repo_id)


async def _vector_search(
    embedding: list[float],
    top_k: int = 5,
    repo_id: int | str | None = None,
    min_similarity: float = 0.5,
) -> list[dict]:
    """Perform HNSW cosine similarity search via pgvector."""
    from sqlalchemy import text

    # pgvector expects a literal like '[0.1, 0.2, ...]'.
    embedding_literal = "[" + ",".join(f"{float(x):.6f}" for x in embedding) + "]"

    where_clauses = ["embedding IS NOT NULL"]
    params: dict[str, object] = {
        "embedding": embedding_literal,
        "top_k": int(top_k),
    }

    if repo_id is not None:
        try:
            params["repo_id"] = int(repo_id)
            where_clauses.append("repo_id = :repo_id")
        except (TypeError, ValueError):
            pass

    where_sql = " AND ".join(where_clauses)

    sql = text(
        f"""
        SELECT id, repo_id, pr_number, vuln_type, cwe, severity,
               description, fix_snippet, file_path, frequency,
               1 - (embedding <=> CAST(:embedding AS vector)) AS similarity
        FROM knowledge_base
        WHERE {where_sql}
        ORDER BY embedding <=> CAST(:embedding AS vector)
        LIMIT :top_k
        """
    )

    session_factory = get_session_factory()
    async with session_factory() as session:
        result = await session.execute(sql, params)
        rows = result.fetchall()

    return [
        {
            "id": str(row.id),
            "repo_id": str(row.repo_id) if row.repo_id is not None else None,
            "pr_number": row.pr_number,
            "vuln_type": row.vuln_type,
            "cwe": row.cwe,
            "severity": row.severity,
            "description": row.description,
            "fix_snippet": row.fix_snippet,
            "file_path": row.file_path,
            "frequency": row.frequency,
            "similarity": float(row.similarity) if row.similarity is not None else 0.0,
        }
        for row in rows
        if (row.similarity or 0.0) > min_similarity
    ]


async def find_similar_findings_by_code(code_snippet: str, top_k: int = 3) -> list[dict]:
    """Find similar past findings given a code snippet."""
    return await search_similar(code_snippet, top_k=top_k)


async def find_fix_for_vulnerability(vuln_type: str, cwe: str | None = None) -> str | None:
    """Look up a fix suggestion for a known vulnerability type."""
    query = f"{vuln_type} {cwe or ''}".strip()
    results = await search_similar(query, top_k=3)

    for r in results:
        if r.get("fix_snippet") and r.get("similarity", 0.0) > 0.7:
            return r["fix_snippet"]

    return None
