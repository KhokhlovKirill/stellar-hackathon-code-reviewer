"""LangChain tool wrapper for on-demand Semgrep scanning."""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import tool


@tool
async def semgrep_scan(file_patches: str) -> str:
    """Run Semgrep SAST on provided file patches and return JSON findings.

    Args:
        file_patches: JSON string of list[{filename, patch}] dicts.

    Returns:
        JSON string of security findings.
    """
    from aegis.pipeline.deterministic.semgrep import run_semgrep
    try:
        files = json.loads(file_patches)
        findings = await run_semgrep(files)
        return json.dumps(findings)
    except Exception as exc:
        return json.dumps({"error": str(exc)})
