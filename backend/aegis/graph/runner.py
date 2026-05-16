"""High-level facade that runs the graph and returns a `SimpleScanResult`.

The point of this layer is API compatibility: every existing endpoint
already speaks the `SimpleScanResult` shape produced by
`run_simple_scan`. By matching that shape exactly, the LangGraph path can
be switched on with a single env flag without touching the API or DB layer.
"""

from __future__ import annotations

from aegis.graph.runtime import execute_graph
from aegis.graph.state import ScanGraphState
from aegis.pipeline.simple_scan import SimpleScanResult


async def run_graph_scan(
    url: str,
    token: str | None = None,
    lang: str = "ru",
) -> SimpleScanResult:
    """Run the LangGraph-orchestrated security review.

    Returns the exact same `SimpleScanResult` dataclass as the direct
    pipeline so callers (REST endpoints, persistence, web/extension UI)
    don't have to branch on which orchestrator ran.
    """
    initial: ScanGraphState = {
        "url": url,
        "token": token,
        "lang": lang,
    }
    final = await execute_graph(initial)

    return SimpleScanResult(
        repo=final.get("slug", ""),
        pr_number=int(final.get("pr_number") or 0),
        pr_title=final.get("pr_title", ""),
        pr_url=final.get("pr_url", url),
        pr_author=final.get("pr_author", ""),
        findings=list(final.get("findings") or []),
        files_scanned=int(final.get("files_scanned") or 0),
        degraded=bool(final.get("degraded_reasons")),
        degraded_reasons=list(final.get("degraded_reasons") or []),
        files_scanned_paths=list(final.get("files_scanned_paths") or []),
        head_sha=final.get("head_sha", ""),
        summary=final.get("summary", ""),
        finding_labels=dict(final.get("finding_labels") or {}),
        error=final.get("error"),
    )
