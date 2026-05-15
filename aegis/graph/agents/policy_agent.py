"""Policy agent — applies repo/org-level security policies."""

from __future__ import annotations

from aegis.graph.state import SecurityGraphState
from aegis.observability.logging import get_logger

log = get_logger(__name__)


async def policy_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Apply security policies to determine final PR status.

    Policies (loaded from repo settings_json):
        - min_severity_to_block: e.g. "high"
        - allowed_cwe: list of CWE IDs that are suppressed
        - require_fix_before_merge: bool
        - auto_approve_low: bool

    Updates:
        - state["policy_decision"]: "block" | "warn" | "pass"
        - state["policy_reasons"]: list[str] explaining the decision
        - state["filtered_final_findings"]: after policy suppression
    """
    final_findings = state.get("final_findings", [])
    risk_label = state.get("risk_label", "")
    has_secret = state.get("has_secret", False)
    human_decision = state.get("human_decision")
    pr_metadata = state.get("pr_metadata", {})
    repo_settings = state.get("repo_settings", {})

    log.info("policy.start", pr=pr_metadata.get("number"), risk=risk_label)

    # Load policy settings with defaults
    min_severity_to_block = repo_settings.get("min_severity_to_block", "high")
    allowed_cwes: set[str] = set(repo_settings.get("allowed_cwe", []))
    require_fix_before_merge = repo_settings.get("require_fix_before_merge", True)

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    block_threshold = severity_order.get(min_severity_to_block, 3)

    reasons: list[str] = []
    filtered_findings: list[dict] = []

    for finding in final_findings:
        cwe = finding.get("cwe", "")
        severity = finding.get("severity", "info")

        # Check allowed CWE list
        if cwe and cwe in allowed_cwes:
            log.debug("policy.cwe_allowed", cwe=cwe)
            continue

        filtered_findings.append(finding)

        # Check if finding triggers block
        sev_level = severity_order.get(severity, 0)
        if sev_level >= block_threshold:
            reasons.append(f"{severity.upper()} finding: {finding.get('vuln_type', 'unknown')} in {finding.get('file_path', '')}")

    # Secrets always block
    if has_secret:
        reasons.insert(0, "Hardcoded secret or high-entropy string detected")

    # Human decision overrides
    if human_decision == "approved":
        log.info("policy.human_approved")
        return {
            **state,
            "policy_decision": "pass",
            "policy_reasons": ["Human reviewer approved"],
            "filtered_final_findings": filtered_findings,
        }
    elif human_decision == "rejected":
        reasons.insert(0, "Human reviewer rejected this PR")

    # Determine final decision
    if reasons or has_secret:
        decision = "block"
    elif any(f.get("severity") in ("medium",) for f in filtered_findings):
        decision = "warn"
    else:
        decision = "pass"

    log.info("policy.complete", decision=decision, reasons=len(reasons))

    return {
        **state,
        "policy_decision": decision,
        "policy_reasons": reasons,
        "filtered_final_findings": filtered_findings,
    }
