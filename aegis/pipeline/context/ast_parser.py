"""AST parsing helpers — extract class/function structure from diff patches."""

from __future__ import annotations

import ast
import re
from typing import Any

from aegis.observability.logging import get_logger

log = get_logger(__name__)

# ── Python AST Parser ─────────────────────────────────────────────────────────


def parse_python_ast(source: str) -> dict[str, Any]:
    """Parse Python source into a lightweight AST summary."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {"error": "syntax_error"}

    summary: dict[str, Any] = {
        "imports": [],
        "functions": [],
        "classes": [],
        "calls": [],
    }

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = getattr(node, "module", "") or ""
            for alias in getattr(node, "names", []):
                summary["imports"].append(f"{module}.{alias.name}" if module else alias.name)

        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            args = [a.arg for a in node.args.args]
            summary["functions"].append({
                "name": node.name,
                "line": node.lineno,
                "args": args,
                "decorators": [_unparse(d) for d in node.decorator_list],
            })

        elif isinstance(node, ast.ClassDef):
            bases = [_unparse(b) for b in node.bases]
            summary["classes"].append({
                "name": node.name,
                "line": node.lineno,
                "bases": bases,
            })

        elif isinstance(node, ast.Call):
            func_name = _unparse(node.func)
            if func_name:
                summary["calls"].append(func_name)

    # Deduplicate calls
    summary["calls"] = list(set(summary["calls"]))[:30]
    return summary


def _unparse(node: ast.expr) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


# ── JavaScript/TypeScript simple regex parser ─────────────────────────────────

_JS_FUNC_RE = re.compile(
    r"(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(|"
    r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\("
)
_JS_CLASS_RE = re.compile(r"class\s+(\w+)")
_JS_IMPORT_RE = re.compile(r"(?:import|require)\s*[\({]?\s*['\"]([^'\"]+)['\"]")


def parse_js_ast(source: str) -> dict[str, Any]:
    """Very lightweight JS/TS structural parser (regex-based)."""
    summary: dict[str, Any] = {"imports": [], "functions": [], "classes": []}
    for line_no, line in enumerate(source.splitlines(), 1):
        for m in _JS_IMPORT_RE.finditer(line):
            summary["imports"].append(m.group(1))
        for m in _JS_FUNC_RE.finditer(line):
            name = m.group(1) or m.group(2)
            if name:
                summary["functions"].append({"name": name, "line": line_no})
        for m in _JS_CLASS_RE.finditer(line):
            summary["classes"].append({"name": m.group(1), "line": line_no})
    return summary


# ── Generic dispatcher ────────────────────────────────────────────────────────


def parse_file_ast(filename: str, source: str) -> dict[str, Any]:
    """Dispatch to the correct parser based on file extension."""
    if filename.endswith(".py"):
        return parse_python_ast(source)
    elif filename.endswith((".js", ".ts", ".jsx", ".tsx")):
        return parse_js_ast(source)
    return {}


async def build_ast_context(
    files: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Build AST context map for all code files.

    Args:
        files: list of DiffFile dicts with 'filename' and 'patch'.

    Returns:
        Mapping path → ast_summary dict.
    """
    context: dict[str, dict[str, Any]] = {}
    for f in files:
        filename = f.get("filename", "")
        patch = f.get("patch", "")
        # Only process added lines for AST
        added_source = "\n".join(
            line[1:] for line in patch.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        if added_source.strip():
            context[filename] = parse_file_ast(filename, added_source)
    return context
