"""Risk agent — computes final risk assessment and determines routing."""

from __future__ import annotations

from aegis.graph.state import SecurityGraphState
from aegis.observability.logging import get_logger
from aegis.observability.metrics import PR_BLOCKED

log = get_logger(__name__)


async def risk_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Compute aggregate risk and set routing flags.

    Updates:
        - state["risk_score"]: normalized 0-100
        - state["risk_label"]: critical/high/medium/low/green
        - state["block_pr"]: bool — whether to block the PR
        - state["risk_breakdown"]: dict with severity counts
    """
    final_findings = state.get("final_findings", [])
    deterministic_findings = state.get("deterministic_findings", [])
    has_secret = state.get("has_secret", False)
    pr_metadata = state.get("pr_metadata", {})
    existing_risk_score = state.get("risk_score", 0)

    log.info("risk.start", pr=pr_metadata.get("number"), findings=len(final_findings))

    # Count findings by severity
    breakdown: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    all_findings = final_findings or deterministic_findings
    for f in all_findings:
        sev = f.get("severity", "info")
        if sev in breakdown:
            breakdown[sev] += 1

    # If judge already computed, refine it
    if existing_risk_score == 0:
        # Compute from scratch
        risk_score = _calc_risk_score(breakdown)
    else:
        risk_score = existing_risk_score

    # Secrets always elevate to critical
    if has_secret:
        risk_score = max(risk_score, 90)
        breakdown["critical"] = max(breakdown["critical"], 1)

    risk_label = _score_to_label(risk_score)

    # Block PR if critical or high findings present, or secrets found
    block_pr = risk_label in ("critical", "high") or has_secret

    if block_pr:
        repo_id = str(state.get("repo_id", "unknown"))
        PR_BLOCKED.labels(repo_id=repo_id).inc()

    log.info(
        "risk.complete",
        risk_score=risk_score,
        risk_label=risk_label,
        block_pr=block_pr,
        breakdown=breakdown,
    )

    return {
        **state,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "block_pr": block_pr,
        "risk_breakdown": breakdown,
    }


def _calc_risk_score(breakdown: dict[str, int]) -> int:
    weights = {"critical": 25, "high": 15, "medium": 5, "low": 1, "info": 0}
    total = sum(weights.get(k, 0) * v for k, v in breakdown.items())
    return min(100, total)


def _score_to_label(score: int) -> str:
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    elif score > 0:
        return "low"
    return "green"
