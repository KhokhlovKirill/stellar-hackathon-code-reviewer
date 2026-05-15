"""LangChain tool for querying the knowledge base (pgvector)."""

from __future__ import annotations

import json

from langchain_core.tools import tool


@tool
async def search_knowledge_base(query: str, top_k: int = 5) -> str:
    """Search the security knowledge base for similar past findings.

    Args:
        query: Semantic search query (e.g., code snippet or vulnerability description).
        top_k: Number of results to return.

    Returns:
        JSON string with similar findings from the knowledge base.
    """
    try:
        from aegis.knowledge.retrieval import search_similar
        results = await search_similar(query, top_k=top_k)
        return json.dumps(results)
    except Exception as exc:
        return json.dumps({"error": str(exc), "results": []})
