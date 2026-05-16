"""deterministic_agent — runs deterministic detectors (secrets, entropy, …).

Currently delegates to `aegis.pipeline.deterministic.secrets.scan_secrets`,
which is the production deterministic surface. New deterministic scanners
plug in here without touching the graph topology.
"""

from __future__ import annotations

from typing import Any

from aegis.graph.agents._trace import traced
from aegis.graph.state import ScanGraphState
from aegis.pipeline.deterministic.secrets import scan_secrets


@traced("deterministic")
async def deterministic_agent(state: ScanGraphState) -> dict[str, Any]:
    code_files = state.get("code_files") or []
    det = scan_secrets(code_files)
    return {"det_findings": det}
