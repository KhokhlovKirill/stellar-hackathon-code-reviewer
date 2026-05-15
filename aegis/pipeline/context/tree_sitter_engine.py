"""Tree-sitter engine for deeper AST analysis of Python and JavaScript."""

from __future__ import annotations

from typing import Any

from aegis.observability.logging import get_logger

log = get_logger(__name__)


def _load_parsers() -> dict[str, Any]:
    """Lazily load tree-sitter parsers."""
    try:
        import tree_sitter_python
        import tree_sitter_javascript
        from tree_sitter import Language, Parser

        PY_LANGUAGE = Language(tree_sitter_python.language())
        JS_LANGUAGE = Language(tree_sitter_javascript.language())

        py_parser = Parser(PY_LANGUAGE)
        js_parser = Parser(JS_LANGUAGE)

        return {"python": py_parser, "javascript": js_parser}
    except Exception as e:
        log.warning("tree_sitter.load_failed", error=str(e))
        return {}


_PARSERS: dict[str, Any] | None = None


def _get_parsers() -> dict[str, Any]:
    global _PARSERS
    if _PARSERS is None:
        _PARSERS = _load_parsers()
    return _PARSERS


def _extract_functions_ts(tree, source_bytes: bytes) -> list[dict[str, Any]]:
    """Walk tree-sitter tree and extract function definitions."""
    functions = []
    cursor = tree.walk()

    def _walk(node) -> None:
        if node.type in ("function_definition", "function_declaration", "method_definition"):
            name_node = node.child_by_field_name("name")
            name = source_bytes[name_node.start_byte:name_node.end_byte].decode() if name_node else "anonymous"
            functions.append({
                "name": name,
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
                "body": source_bytes[node.start_byte:node.end_byte].decode(errors="replace")[:500],
            })
        for child in node.children:
            _walk(child)

    _walk(tree.root_node)
    return functions


async def analyze_with_tree_sitter(
    filename: str,
    source: str,
) -> dict[str, Any]:
    """Run tree-sitter analysis and return function/class summaries."""
    parsers = _get_parsers()
    if not parsers:
        return {}

    language = None
    if filename.endswith(".py"):
        language = "python"
    elif filename.endswith((".js", ".ts", ".jsx", ".tsx")):
        language = "javascript"

    if not language or language not in parsers:
        return {}

    try:
        parser = parsers[language]
        source_bytes = source.encode("utf-8", errors="replace")
        tree = parser.parse(source_bytes)
        functions = _extract_functions_ts(tree, source_bytes)
        return {
            "language": language,
            "functions": functions,
            "node_count": tree.root_node.child_count,
            "has_errors": tree.root_node.has_error,
        }
    except Exception as exc:
        log.debug("tree_sitter.parse_error", filename=filename, error=str(exc))
        return {}
