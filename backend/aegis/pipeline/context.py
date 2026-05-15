"""Smart Context Window stage.

Fetches only the changed file contents at the PR head and extracts a bounded
window around each changed hunk. This is not whole-repo analysis; it is narrow
context for the LLM so it can see nearby validation/sanitization code.
"""

from __future__ import annotations

import ast
import asyncio
import re

from aegis.config import get_config
from aegis.obs import get_logger
from aegis.pipeline.state import PipelineState
from aegis.providers import get_provider
from aegis.schemas import FileChange
from aegis.tokenest import estimate_tokens

log = get_logger("aegis.context")


async def enrich_context(state: PipelineState) -> None:
    if not state.code_files or not state.ctx.access_token:
        return

    provider = get_provider(state.ev.provider)
    limit = get_config().diff.context_lines

    async def _fetch(fc: FileChange) -> tuple[str, str | None]:
        try:
            return fc.path, await provider.fetch_file(state.pr, state.ctx.access_token, fc.path)
        except Exception as exc:
            log.warning("context.fetch_failed", scan_id=state.scan_id, path=fc.path, error=str(exc))
            return fc.path, None

    fetched = await asyncio.gather(*[_fetch(fc) for fc in state.code_files])
    by_path = dict(fetched)
    context_map: dict[str, str] = {}
    for fc in state.code_files:
        text = by_path.get(fc.path)
        if not text:
            continue
        context = extract_context(fc, text, limit)
        rag = extract_python_call_context(fc, text)
        if rag:
            context = f"{context}\n{rag}" if context else rag
        if context:
            context_map[fc.path] = context

    state.context_map = context_map
    log.info(
        "context.enriched",
        scan_id=state.scan_id,
        files=len(context_map),
        est_context_tokens=sum(estimate_tokens(v) for v in context_map.values()),
    )


def extract_context(fc: FileChange, file_text: str, context_lines: int) -> str:
    lines = file_text.splitlines()
    if not lines:
        return ""
    intervals: list[tuple[int, int]] = []
    for hunk in fc.hunks:
        start = max(1, hunk.new_start - context_lines)
        end = min(len(lines), hunk.new_start + hunk.new_count + context_lines - 1)
        intervals.append((start, end))
    merged = _merge_intervals(intervals)
    parts: list[str] = []
    for start, end in merged:
        parts.append(f"@@ context {fc.path}:{start}-{end} @@")
        for lineno in range(start, end + 1):
            parts.append(f"{lineno}: {lines[lineno - 1]}")
    return "\n".join(parts)


def _merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not intervals:
        return []
    ordered = sorted(intervals)
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def extract_python_call_context(fc: FileChange, file_text: str, max_chars: int = 8000) -> str:
    if fc.language != "python" and not fc.path.endswith(".py"):
        return ""
    calls = _added_call_names(fc)
    if not calls:
        return ""
    try:
        tree = ast.parse(file_text)
    except SyntaxError:
        return ""
    lines = file_text.splitlines()
    chunks: list[str] = []
    total = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in calls:
            continue
        end = getattr(node, "end_lineno", node.lineno)
        body = "\n".join(
            f"{lineno}: {lines[lineno - 1]}" for lineno in range(node.lineno, end + 1)
        )
        chunk = f"@@ ast-context {fc.path}:{node.name}:{node.lineno}-{end} @@\n{body}"
        if total + len(chunk) > max_chars:
            break
        chunks.append(chunk)
        total += len(chunk)
    return "\n".join(chunks)


def _added_call_names(fc: FileChange) -> set[str]:
    calls: set[str] = set()
    for line in fc.added_lines():
        for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", line.content):
            if name not in {"if", "for", "while", "with", "return", "print"}:
                calls.add(name)
    return calls
