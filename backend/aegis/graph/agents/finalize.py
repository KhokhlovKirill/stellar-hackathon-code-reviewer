"""finalize_agent — set timestamps and overall status.

This is the END node of the graph. It exists so we have a single place where
the run wall-clock is closed and a per-graph `status` field is computed; the
runner converts the final state into a `SimpleScanResult` for the API layer.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from aegis.graph.agents._trace import traced
from aegis.graph.state import ScanGraphState


@traced("finalize")
async def finalize_agent(state: ScanGraphState) -> dict[str, Any]:
    return {
        "finished_at": datetime.now(UTC).isoformat(),
        "status": "error" if state.get("error") else "ok",
    }
