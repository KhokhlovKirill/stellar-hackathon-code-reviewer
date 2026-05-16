"""parse_agent — parse a GitHub/GitLab URL into provider + slug + number."""

from __future__ import annotations

from typing import Any

from aegis.graph.agents._trace import traced
from aegis.graph.state import ScanGraphState
from aegis.pipeline.simple_scan import _parse_repo_url


@traced("parse")
async def parse_agent(state: ScanGraphState) -> dict[str, Any]:
    url = state.get("url", "")
    try:
        kind, api_base, slug, number = _parse_repo_url(url)
    except ValueError as exc:
        return {"error": str(exc), "slug": "", "pr_number": 0}
    return {
        "provider_kind": kind,
        "api_base": api_base,
        "slug": slug,
        "pr_number": number or 0,
        "pr_url": url,
    }
