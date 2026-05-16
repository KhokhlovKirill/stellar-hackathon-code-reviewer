"""fetch_pr_agent + fetch_diff_agent — fetch PR metadata and unified diff."""

from __future__ import annotations

from typing import Any

from aegis.graph.agents._trace import traced
from aegis.graph.state import ScanGraphState
from aegis.pipeline.simple_scan import _fetch_changes, _fetch_latest, _fetch_one


@traced("fetch_pr")
async def fetch_pr_agent(state: ScanGraphState) -> dict[str, Any]:
    kind = state.get("provider_kind", "github")
    api_base = state.get("api_base", "https://api.github.com")
    slug = state.get("slug", "")
    pr_number = state.get("pr_number") or None
    token = state.get("token")

    try:
        if not pr_number:
            pr_data = await _fetch_latest(kind, api_base, slug, token)
            pr_number = int(pr_data["number"])
        else:
            pr_data = await _fetch_one(kind, api_base, slug, pr_number, token)
    except ValueError as exc:
        return {"error": str(exc)}

    return {
        "pr_number": pr_number,
        "pr_title": pr_data.get("title", f"PR #{pr_number}"),
        "pr_url": pr_data.get("html_url", state.get("pr_url", "")),
        "pr_author": (pr_data.get("user") or {}).get("login", "unknown"),
        "head_sha": ((pr_data.get("head") or {}).get("sha") or ""),
    }


@traced("fetch_diff")
async def fetch_diff_agent(state: ScanGraphState) -> dict[str, Any]:
    kind = state.get("provider_kind", "github")
    api_base = state.get("api_base", "https://api.github.com")
    slug = state.get("slug", "")
    pr_number = int(state.get("pr_number") or 0)
    token = state.get("token")
    try:
        diff_text = await _fetch_changes(kind, api_base, slug, pr_number, token)
    except ValueError as exc:
        return {"error": str(exc)}
    return {"diff_text": diff_text}
