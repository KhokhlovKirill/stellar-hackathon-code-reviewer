"""Blast radius agent — estimates the impact scope of vulnerabilities."""

from __future__ import annotations

from aegis.graph.state import SecurityGraphState
from aegis.observability.logging import get_logger

log = get_logger(__name__)


async def blast_radius_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Analyse the blast radius: which files/functions are impacted.

    Updates:
        - state["blast_radius"]: dict with affected files, call chains, exposure
    """
    final_findings = state.get("final_findings", [])
    import_graph = state.get("import_graph", {})
    pr_metadata = state.get("pr_metadata", {})

    log.info("blast_radius.start", findings=len(final_findings))

    affected_files: set[str] = set()
    exposure_details: list[dict] = []

    for finding in final_findings:
        file_path = finding.get("file_path", "")
        if not file_path:
            continue

        affected_files.add(file_path)

        # Find files that import the affected file
        dependents = _find_dependents(file_path, import_graph)
        affected_files.update(dependents)

        exposure_details.append({
            "finding_type": finding.get("vuln_type", ""),
            "file": file_path,
            "severity": finding.get("severity", ""),
            "direct_dependents": list(dependents),
            "exposure": _estimate_exposure(finding),
        })

    blast_radius = {
        "affected_files": sorted(affected_files),
        "affected_count": len(affected_files),
        "exposure_details": exposure_details,
        "total_exposure_score": _total_exposure(exposure_details),
    }

    log.info(
        "blast_radius.complete",
        affected_files=len(affected_files),
        exposure_score=blast_radius["total_exposure_score"],
    )

    return {**state, "blast_radius": blast_radius}


def _find_dependents(file_path: str, import_graph: dict) -> set[str]:
    """Find files that directly import the given file."""
    dependents: set[str] = set()
    basename = file_path.split("/")[-1].replace(".py", "").replace(".js", "")
    for fname, imports in import_graph.items():
        if any(basename in imp for imp in imports):
            dependents.add(fname)
    return dependents


def _estimate_exposure(finding: dict) -> str:
    """Rough exposure estimate based on vuln type and severity."""
    vuln_type = finding.get("vuln_type", "").lower()
    severity = finding.get("severity", "")

    if severity == "critical":
        return "full_system"
    if any(t in vuln_type for t in ("sql", "injection", "rce", "ssrf")):
        return "data_exfiltration"
    if any(t in vuln_type for t in ("xss", "csrf")):
        return "user_accounts"
    if any(t in vuln_type for t in ("secret", "credential")):
        return "infrastructure"
    return "limited"


def _total_exposure(details: list[dict]) -> int:
    exposure_weights = {
        "full_system": 40,
        "data_exfiltration": 30,
        "infrastructure": 25,
        "user_accounts": 15,
        "limited": 5,
    }
    return min(100, sum(exposure_weights.get(d.get("exposure", "limited"), 5) for d in details))
