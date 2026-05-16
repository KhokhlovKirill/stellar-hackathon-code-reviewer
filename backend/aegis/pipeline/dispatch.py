"""Single entry point that picks the active orchestrator at runtime.

Both `run_simple_scan` (direct path) and `run_graph_scan` (LangGraph path)
return the same `SimpleScanResult`, so callers depend only on the result
shape — not on which orchestrator produced it.

Selection: `AEGIS_USE_LANGGRAPH=1` in env / settings flips the runtime
default. An explicit `prefer_graph=True` argument forces the graph path
regardless of the global setting (used by `/api/ext/scan/graph/url`).
"""

from __future__ import annotations

from aegis.config import get_settings
from aegis.obs import get_logger
from aegis.pipeline.simple_scan import SimpleScanResult, run_simple_scan

log = get_logger("aegis.pipeline.dispatch")


async def run_scan(
    url: str,
    token: str | None = None,
    lang: str = "ru",
    *,
    prefer_graph: bool | None = None,
) -> SimpleScanResult:
    """Run a pull-mode scan via the configured orchestrator.

    `prefer_graph=True/False` overrides the global setting for a single
    call; `None` (default) uses `Settings.use_langgraph`.
    """
    use_graph = (
        prefer_graph if prefer_graph is not None else get_settings().use_langgraph
    )
    if use_graph:
        try:
            from aegis.graph.runner import run_graph_scan
        except ImportError as exc:
            # langgraph dependency not installed in this environment — fall back.
            log.warning("dispatch.langgraph_unavailable", error=str(exc))
            return await run_simple_scan(url, token, lang=lang)

        log.info("dispatch.route", orchestrator="langgraph")
        return await run_graph_scan(url, token, lang=lang)

    log.info("dispatch.route", orchestrator="simple_scan")
    return await run_simple_scan(url, token, lang=lang)
