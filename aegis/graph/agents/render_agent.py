"""Render agent — formats findings into human-readable comments."""

from __future__ import annotations

from aegis.graph.state import SecurityGraphState
from aegis.observability.logging import get_logger

log = get_logger(__name__)

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "green": "✅",
}

_BADGE_COLORS = {
    "critical": "critical",
    "high": "important",
    "medium": "yellow",
    "low": "informational",
    "green": "success",
}


async def render_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Render findings as Markdown for PR comment publication.

    Updates:
        - state["pr_comment_body"]: main comment markdown string
        - state["inline_comments"]: list[{path, line, body}] for inline comments
        - state["status_check"]: {state, description, context} for GitHub status
    """
    filtered_final_findings = state.get("filtered_final_findings") or state.get("final_findings", [])
    autofix_suggestions = state.get("autofix_suggestions", [])
    risk_score = state.get("risk_score", 0)
    risk_label = state.get("risk_label", "green")
    risk_breakdown = state.get("risk_breakdown", {})
    policy_decision = state.get("policy_decision", "pass")
    policy_reasons = state.get("policy_reasons", [])
    blast_radius = state.get("blast_radius", {})
    pr_metadata = state.get("pr_metadata", {})
    llm_a_summary = state.get("llm_a_summary", "")
    scan_id = state.get("scan_id", "")

    log.info("render.start", findings=len(filtered_final_findings), risk=risk_label)

    # Build main comment
    comment_body = _render_main_comment(
        findings=filtered_final_findings,
        risk_score=risk_score,
        risk_label=risk_label,
        risk_breakdown=risk_breakdown,
        policy_decision=policy_decision,
        policy_reasons=policy_reasons,
        blast_radius=blast_radius,
        summary=llm_a_summary,
        autofix_suggestions=autofix_suggestions,
        scan_id=scan_id,
    )

    # Build inline comments for high/critical findings with line numbers
    inline_comments = _render_inline_comments(filtered_final_findings, autofix_suggestions)

    # Build status check
    status_check = _render_status_check(risk_label, risk_score, policy_decision)

    log.info("render.complete", inline_comments=len(inline_comments))

    return {
        **state,
        "pr_comment_body": comment_body,
        "inline_comments": inline_comments,
        "status_check": status_check,
    }


def _render_main_comment(
    findings: list[dict],
    risk_score: int,
    risk_label: str,
    risk_breakdown: dict,
    policy_decision: str,
    policy_reasons: list[str],
    blast_radius: dict,
    summary: str,
    autofix_suggestions: list[dict],
    scan_id: str,
) -> str:
    emoji = _SEVERITY_EMOJI.get(risk_label, "⚪")
    badge_color = _BADGE_COLORS.get(risk_label, "informational")

    lines = [
        f"## {emoji} Aegis Security Review",
        "",
        f"![Risk Score](https://img.shields.io/badge/Risk%20Score-{risk_score}-{badge_color})",
        f"![Status](https://img.shields.io/badge/Status-{policy_decision.upper()}-{'critical' if policy_decision == 'block' else 'success'})",
        "",
    ]

    if summary:
        lines += ["### Summary", "", summary, ""]

    # Risk breakdown
    lines += ["### Risk Breakdown", ""]
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = risk_breakdown.get(sev, 0)
        if count > 0:
            sev_emoji = _SEVERITY_EMOJI.get(sev, "⚪")
            lines.append(f"| {sev_emoji} {sev.capitalize()} | {count} |")
    lines.append("")

    # Findings
    if findings:
        lines += ["### Findings", ""]
        for i, finding in enumerate(findings[:20], 1):  # limit display
            sev = finding.get("severity", "info")
            sev_emoji = _SEVERITY_EMOJI.get(sev, "⚪")
            file_path = finding.get("file_path", "")
            line_no = finding.get("line_number", "?")
            vuln_type = finding.get("vuln_type", "Unknown")
            cwe = finding.get("cwe", "")
            desc = finding.get("description", "")

            lines.append(f"#### {i}. {sev_emoji} [{sev.upper()}] {vuln_type}")
            lines.append(f"- **File**: `{file_path}` (line {line_no})")
            if cwe:
                lines.append(f"- **CWE**: [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html)")
            lines.append(f"- **Description**: {desc}")

            # Check for autofix
            fix = next((s for s in autofix_suggestions if s.get("file") == file_path), None)
            if fix:
                lines.append(f"- **Fix available** ✨")
                lines.append(f"```suggestion")
                lines.append(fix.get("fix", ""))
                lines.append("```")

            lines.append("")

        if len(findings) > 20:
            lines.append(f"_...and {len(findings) - 20} more findings. See full report._")
            lines.append("")

    # Blast radius
    affected_count = blast_radius.get("affected_count", 0)
    if affected_count > 0:
        lines += [
            "### Blast Radius",
            "",
            f"**{affected_count} files** potentially affected by the vulnerabilities found.",
            "",
        ]

    # Policy decision
    if policy_decision == "block":
        lines += [
            "---",
            "### ❌ PR Blocked",
            "",
            "This PR cannot be merged until the following issues are resolved:",
        ]
        for reason in policy_reasons[:5]:
            lines.append(f"- {reason}")
        lines.append("")
    elif policy_decision == "warn":
        lines += [
            "---",
            "### ⚠️ PR Warnings",
            "",
            "The following issues were found but do not block merge:",
        ]
        for reason in policy_reasons[:5]:
            lines.append(f"- {reason}")
        lines.append("")

    # Footer
    lines += [
        "---",
        f"_Scan ID: `{scan_id}` | Powered by [Aegis DevSecOps](https://github.com/aegis) | `/secbot help` for commands_",
    ]

    return "\n".join(lines)


def _render_inline_comments(findings: list[dict], autofix_suggestions: list[dict]) -> list[dict]:
    inline: list[dict] = []
    for finding in findings:
        sev = finding.get("severity", "")
        if sev not in ("critical", "high"):
            continue
        line_no = finding.get("line_number")
        if not line_no:
            continue

        file_path = finding.get("file_path", "")
        vuln_type = finding.get("vuln_type", "")
        desc = finding.get("description", "")
        cwe = finding.get("cwe", "")

        fix = next((s for s in autofix_suggestions if s.get("file") == file_path), None)

        body_parts = [
            f"🔐 **{vuln_type}**",
            f"> {desc}",
        ]
        if cwe:
            body_parts.append(f"**{cwe}**")
        if fix:
            body_parts.append(f"\n**Suggested fix:**\n```suggestion\n{fix.get('fix', '')}\n```")

        inline.append({
            "path": file_path,
            "line": line_no,
            "body": "\n".join(body_parts),
        })

    return inline


def _render_status_check(risk_label: str, risk_score: int, policy_decision: str) -> dict:
    if policy_decision == "block":
        state = "failure"
        description = f"Security issues found (risk score: {risk_score}/100)"
    elif policy_decision == "warn":
        state = "pending"
        description = f"Security warnings present (risk score: {risk_score}/100)"
    else:
        state = "success"
        description = f"No critical security issues (risk score: {risk_score}/100)"

    return {
        "state": state,
        "description": description,
        "context": "aegis/security-review",
    }
