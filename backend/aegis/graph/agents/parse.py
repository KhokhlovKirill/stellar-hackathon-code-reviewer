"""parse_agent — parse the GitHub URL into (slug, pr_number)."""

from __future__ import annotations

from typing import Any

from aegis.graph.agents._trace import traced
from aegis.graph.state import ScanGraphState
from aegis.pipeline.simple_scan import _parse_github_url


@traced("parse")
async def parse_agent(state: ScanGraphState) -> dict[str, Any]:
    url = state.get("url", "")
    try:
        slug, pr_number = _parse_github_url(url)
    except ValueError as exc:
        return {"error": str(exc), "slug": "", "pr_number": 0}
    return {
        "slug": slug,
        "pr_number": pr_number or 0,
        "pr_url": url,
    }
