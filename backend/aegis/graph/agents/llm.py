"""llm_agent — run the production LLM ensemble (OpenRouter + Don) over the diff.

Delegates to `aegis.pipeline.simple_scan._run_llm`, which is the
authoritative implementation: parallel detectors A/B, judge arbitration,
mandatory Don tier, ensemble dedup, degraded-tier reporting.
"""

from __future__ import annotations

from typing import Any

from aegis.graph.agents._trace import traced
from aegis.graph.state import ScanGraphState
from aegis.pipeline.simple_scan import _run_llm
from aegis.schemas import Severity


@traced("llm")
async def llm_agent(state: ScanGraphState) -> dict[str, Any]:
    slug = state.get("slug", "")
    pr_number = int(state.get("pr_number") or 0)
    code_files = state.get("code_files") or []
    det_findings = state.get("det_findings") or []

    findings, degraded_reasons = await _run_llm(slug, pr_number, code_files, det_findings)

    # Free memory — unload LM Studio if swap mode is enabled. Mirrors
    # the behaviour of `run_simple_scan` so the graph path doesn't leak.
    try:
        from aegis.config import get_settings
        from aegis.llm.lmstudio_manager import unload_all

        s = get_settings()
        if s.lmstudio_swap_models:
            await unload_all(s.lmstudio_base_url)
    except Exception as exc:
        # Non-fatal: LM Studio swap is a cleanup hook, not part of the result.
        from aegis.obs import get_logger

        get_logger("aegis.graph.llm").debug("graph.llm.unload_failed", error=str(exc))

    _sev_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }
    findings.sort(key=lambda f: _sev_order.get(f.severity, 9))

    return {"findings": findings, "degraded_reasons": degraded_reasons}
