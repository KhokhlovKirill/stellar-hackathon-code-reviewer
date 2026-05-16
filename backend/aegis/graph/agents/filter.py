"""filter_agent — parse diff and keep only security-relevant files."""

from __future__ import annotations

from typing import Any

from aegis.graph.agents._trace import traced
from aegis.graph.state import ScanGraphState
from aegis.pipeline.simple_scan import _filter_files
from aegis.providers.diffparse import parse_unified_diff


@traced("filter")
async def filter_agent(state: ScanGraphState) -> dict[str, Any]:
    diff_text = state.get("diff_text", "")
    if not diff_text:
        return {"all_files": [], "code_files": [], "files_scanned": 0, "skip_llm": True}

    try:
        all_files = parse_unified_diff(diff_text)
    except Exception as exc:
        return {"error": f"Diff parse error: {exc}"}

    code_files = _filter_files(all_files)
    return {
        "all_files": all_files,
        "code_files": code_files,
        "files_scanned": len(code_files),
        "files_scanned_paths": [f.path for f in code_files],
        "skip_llm": len(code_files) == 0,
    }
