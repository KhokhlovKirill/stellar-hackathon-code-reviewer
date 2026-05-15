"""Risk score stage.

The score is intentionally deterministic and explainable: each finding contributes
by CWE/rule/severity, capped per bucket so duplicate lines do not dominate a PR.
"""

from __future__ import annotations

from collections import defaultdict

from aegis.obs import get_logger
from aegis.pipeline.state import PipelineState
from aegis.schemas import Finding, Severity

log = get_logger("aegis.risk_score")

_CWE_WEIGHTS = {
    "CWE-89": 40,    # SQL injection
    "CWE-798": 35,   # hardcoded credential
    "CWE-79": 30,    # XSS
    "CWE-94": 35,    # code injection
    "CWE-78": 35,    # command injection
    "CWE-918": 35,   # SSRF
    "CWE-22": 25,    # path traversal
    "CWE-502": 30,   # unsafe deserialization
    "CWE-321": 30,   # hardcoded cryptographic key
    "CWE-1395": 15,  # vulnerable dependency
}

_SEVERITY_FALLBACK = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 1,
}


async def compute_risk_score(state: PipelineState) -> None:
    breakdown = risk_breakdown(state.findings)
    score = min(sum(breakdown.values()), 100)
    label = risk_label(score, state.findings)
    state.risk_score = score
    state.risk_label = label
    state.result.risk_score = score
    state.result.risk_label = label
    state.result.findings = list(state.findings)
    log.info(
        "risk_score.computed",
        scan_id=state.scan_id,
        score=score,
        label=label,
        breakdown=dict(breakdown),
    )


def risk_breakdown(findings: list[Finding]) -> dict[str, int]:
    totals: dict[str, int] = defaultdict(int)
    for f in findings:
        key = f.cwe or f.rule_id or f.severity.value
        weight = _weight(f)
        cap = max(weight * 2, weight)
        totals[key] = min(totals[key] + weight, cap)
    return dict(totals)


def risk_label(score: int, findings: list[Finding]) -> str:
    if any(f.severity is Severity.CRITICAL for f in findings):
        return "critical"
    if score > 60:
        return "high"
    if score > 30:
        return "medium"
    return "low"


def _weight(finding: Finding) -> int:
    if finding.cwe in _CWE_WEIGHTS:
        return _CWE_WEIGHTS[finding.cwe]
    if finding.rule_id == "secret:high-entropy":
        return 20
    return _SEVERITY_FALLBACK[finding.severity]
