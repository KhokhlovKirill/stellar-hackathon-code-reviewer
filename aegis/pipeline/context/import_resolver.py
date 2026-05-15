"""Import resolver — build a dependency graph from diff imports."""

from __future__ import annotations

import re
from typing import Any

from aegis.observability.logging import get_logger

log = get_logger(__name__)

_PY_IMPORT_RE = re.compile(
    r"^(?:from\s+([\w.]+)\s+import\s+[\w\s,*]+|import\s+([\w.]+))",
    re.MULTILINE,
)
_JS_IMPORT_RE = re.compile(
    r'(?:import\s+.*?from\s+|require\s*\(\s*)["\']([^"\']+)["\']',
)


def extract_imports(patch: str, lang: str) -> list[str]:
    """Extract import statements from a single file's diff patch.

    Args:
        patch: raw unified-diff patch string (may contain +/- markers).
        lang: "python" or "js".

    Returns:
        Deduplicated list of imported module/path names.
    """
    added_lines = "\n".join(
        line[1:] for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    imports: list[str] = []
    if lang == "python":
        for m in _PY_IMPORT_RE.finditer(added_lines):
            module = m.group(1) or m.group(2)
            if module:
                imports.append(module)
    elif lang == "js":
        for m in _JS_IMPORT_RE.finditer(added_lines):
            imports.append(m.group(1))
    return list(set(imports))


def resolve_imports(files: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Extract import statements from all changed files.

    Returns:
        Mapping filename → list of imported module names.
    """
    imports_map: dict[str, list[str]] = {}

    for f in files:
        filename = f.get("filename", "")
        patch = f.get("patch", "")
        added_lines = "\n".join(
            line[1:] for line in patch.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )

        imports: list[str] = []

        if filename.endswith(".py"):
            for m in _PY_IMPORT_RE.finditer(added_lines):
                module = m.group(1) or m.group(2)
                if module:
                    imports.append(module)

        elif filename.endswith((".js", ".ts", ".jsx", ".tsx")):
            for m in _JS_IMPORT_RE.finditer(added_lines):
                imports.append(m.group(1))

        if imports:
            imports_map[filename] = list(set(imports))

    return imports_map


def build_dependency_graph(imports_map: dict[str, list[str]]) -> dict[str, Any]:
    """Build a simple adjacency list representing cross-file imports."""
    try:
        import networkx as nx
        G = nx.DiGraph()
        for file, deps in imports_map.items():
            G.add_node(file)
            for dep in deps:
                G.add_edge(file, dep)
        return {
            "nodes": list(G.nodes),
            "edges": list(G.edges),
            "isolated": [n for n in nx.isolates(G)],
        }
    except ImportError:
        return {"nodes": list(imports_map.keys()), "edges": [], "isolated": []}
