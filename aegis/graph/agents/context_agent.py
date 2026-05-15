"""Context agent — enriches state with AST, imports, and RAG data."""

from __future__ import annotations

import asyncio

from aegis.graph.state import SecurityGraphState
from aegis.observability.logging import get_logger
from aegis.pipeline.context.ast_parser import parse_python_ast, parse_js_ast
from aegis.pipeline.context.import_resolver import extract_imports
from aegis.pipeline.context.code_rag import search_similar_findings

log = get_logger(__name__)


async def context_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Enrich state with code context: AST info, imports, dependency graph, RAG results.

    Updates:
        - state["ast_context"]: dict[filename, {functions, classes, imports}]
        - state["import_graph"]: dict[filename, list[str]] of dependencies
        - state["rag_context"]: list of similar historical findings
    """
    filtered_files = state.get("filtered_files", [])
    file_classifications = state.get("file_classifications", {})

    log.info("context.start", files=len(filtered_files))

    ast_tasks = []
    import_tasks = []

    for file in filtered_files:
        filename: str = file.get("filename", "")
        patch: str = file.get("patch", "")
        cats = file_classifications.get(filename, [])

        if "python" in cats:
            ast_tasks.append(_parse_python(filename, patch))
            import_tasks.append(_extract_file_imports(filename, patch, "python"))
        elif any(c in cats for c in ("javascript",)):
            ast_tasks.append(_parse_js(filename, patch))
            import_tasks.append(_extract_file_imports(filename, patch, "js"))

    # Run AST parsing concurrently
    ast_results_list = await asyncio.gather(*ast_tasks, return_exceptions=True)
    import_results_list = await asyncio.gather(*import_tasks, return_exceptions=True)

    ast_context: dict = {}
    for result in ast_results_list:
        if isinstance(result, Exception):
            log.warning("context.ast_error", error=str(result))
            continue
        if result:
            filename, data = result
            ast_context[filename] = data

    import_graph: dict = {}
    for result in import_results_list:
        if isinstance(result, Exception):
            log.warning("context.import_error", error=str(result))
            continue
        if result:
            filename, imports = result
            import_graph[filename] = imports

    # RAG lookup: search for similar past findings based on function names
    rag_context = []
    all_functions = []
    for data in ast_context.values():
        all_functions.extend(data.get("functions", []))

    if all_functions:
        try:
            query = " ".join(all_functions[:10])
            rag_context = await search_similar_findings(query, top_k=5)
        except Exception as exc:
            log.warning("context.rag_error", error=str(exc))

    log.info(
        "context.complete",
        ast_files=len(ast_context),
        rag_results=len(rag_context),
    )

    return {
        **state,
        "ast_context": ast_context,
        "import_graph": import_graph,
        "rag_context": rag_context,
    }


async def _parse_python(filename: str, patch: str) -> tuple[str, dict] | None:
    try:
        data = parse_python_ast(patch)
        return filename, data
    except Exception as exc:
        log.debug("context.python_ast_fail", filename=filename, error=str(exc))
        return None


async def _parse_js(filename: str, patch: str) -> tuple[str, dict] | None:
    try:
        data = parse_js_ast(patch)
        return filename, data
    except Exception as exc:
        log.debug("context.js_ast_fail", filename=filename, error=str(exc))
        return None


async def _extract_file_imports(filename: str, patch: str, lang: str) -> tuple[str, list] | None:
    try:
        imports = extract_imports(patch, lang)
        return filename, imports
    except Exception as exc:
        log.debug("context.import_fail", filename=filename, error=str(exc))
        return None
