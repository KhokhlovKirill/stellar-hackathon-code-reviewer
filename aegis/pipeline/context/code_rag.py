"""Code RAG — retrieve related function bodies from the knowledge base."""

from __future__ import annotations

from typing import Any

from aegis.observability.logging import get_logger

log = get_logger(__name__)


async def build_code_rag_context(
    files: list[dict[str, Any]],
    ast_context: dict[str, dict[str, Any]],
    repo_slug: str,
    repo_db_id: int,
) -> dict[str, list[str]]:
    """Retrieve historically similar findings for each changed file.

    Queries the pgvector knowledge base for similar vulnerability descriptions
    that match the function signatures found in the diff.

    Returns:
        Mapping path → list of related code snippets / descriptions.
    """
    try:
        from aegis.knowledge.retrieval import search_similar_by_text
    except ImportError:
        return {}

    rag_context: dict[str, list[str]] = {}

    for f in files:
        filename = f.get("filename", "")
        ast_info = ast_context.get(filename, {})
        functions = ast_info.get("functions", [])

        if not functions:
            continue

        # Build a short query from function signatures
        fn_names = [fn["name"] for fn in functions[:5]]
        query = f"Security vulnerability in {filename}: functions {', '.join(fn_names)}"

        try:
            similar = await search_similar_by_text(query=query, top_k=3, repo_id=repo_db_id)
            rag_context[filename] = [item.get("description", "") for item in similar]
        except Exception as exc:
            log.debug("code_rag.query_failed", filename=filename, error=str(exc))

    return rag_context
