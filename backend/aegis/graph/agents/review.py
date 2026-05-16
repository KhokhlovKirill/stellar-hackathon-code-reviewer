"""review_agent — coordinator LLM generates scan summary + per-finding labels."""

from __future__ import annotations

from typing import Any

from aegis.graph.agents._trace import traced
from aegis.graph.state import ScanGraphState
from aegis.pipeline.simple_scan import _generate_scan_review


@traced("review")
async def review_agent(state: ScanGraphState) -> dict[str, Any]:
    summary, labels = await _generate_scan_review(
        state.get("slug", ""),
        int(state.get("pr_number") or 0),
        state.get("pr_title", ""),
        int(state.get("files_scanned") or 0),
        state.get("findings") or [],
        state.get("degraded_reasons") or [],
        lang=state.get("lang", "ru"),
    )
    return {"summary": summary, "finding_labels": labels}
