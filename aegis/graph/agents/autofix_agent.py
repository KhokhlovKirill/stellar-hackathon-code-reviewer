"""Autofix agent — generates code fixes for detected vulnerabilities."""

from __future__ import annotations

from aegis.graph.state import SecurityGraphState
from aegis.llm.router import call_llm
from aegis.llm.prompts.security_review import SYSTEM_PROMPT_AUTOFIX
from aegis.observability.logging import get_logger

log = get_logger(__name__)

_AUTOFIX_ELIGIBLE_SEVERITIES = {"critical", "high", "medium"}


async def autofix_agent(state: SecurityGraphState) -> SecurityGraphState:
    """Generate fix suggestions for high/critical findings.

    Updates:
        - state["autofix_suggestions"]: list[{file, line, original, fixed, explanation}]
        - state["autofix_pr_possible"]: bool
    """
    filtered_final_findings = state.get("filtered_final_findings") or state.get("final_findings", [])
    filtered_files = state.get("filtered_files", [])
    repo_settings = state.get("repo_settings", {})

    autofix_enabled = repo_settings.get("autofix_enabled", True)
    if not autofix_enabled:
        log.info("autofix.disabled")
        return {**state, "autofix_suggestions": [], "autofix_pr_possible": False}

    # Only attempt fixes for eligible findings
    eligible = [
        f for f in filtered_final_findings
        if f.get("severity") in _AUTOFIX_ELIGIBLE_SEVERITIES
    ][:10]  # cap to avoid massive token usage

    log.info("autofix.start", eligible_findings=len(eligible))

    if not eligible:
        return {**state, "autofix_suggestions": [], "autofix_pr_possible": False}

    # Build file content map
    file_map = {f.get("filename", ""): f.get("patch", "") for f in filtered_files}

    suggestions: list[dict] = []

    for finding in eligible:
        file_path = finding.get("file_path", "")
        patch = file_map.get(file_path, "")

        if not patch:
            continue

        # Check if finding already has a fix snippet
        existing_fix = finding.get("fix_snippet")
        if existing_fix:
            suggestions.append({
                "file": file_path,
                "line": finding.get("line_number"),
                "vuln_type": finding.get("vuln_type", ""),
                "severity": finding.get("severity", ""),
                "fix": existing_fix,
                "description": finding.get("description", ""),
                "source": "pre_generated",
            })
            continue

        # Ask LLM to generate fix
        try:
            fix_prompt = _build_fix_prompt(finding, patch)
            response, tokens = await call_llm(
                system=SYSTEM_PROMPT_AUTOFIX,
                user=fix_prompt,
                model_hint="primary",
                pr_id=state.get("pr_id"),
            )
            fix_code = _extract_fix_code(response)
            if fix_code:
                suggestions.append({
                    "file": file_path,
                    "line": finding.get("line_number"),
                    "vuln_type": finding.get("vuln_type", ""),
                    "severity": finding.get("severity", ""),
                    "fix": fix_code,
                    "description": finding.get("description", ""),
                    "source": "llm_generated",
                    "tokens": tokens,
                })
        except Exception as exc:
            log.warning("autofix.llm_error", finding=finding.get("vuln_type"), error=str(exc))

    # Can create a fix PR if we have at least one LLM-generated fix
    autofix_pr_possible = any(s.get("source") == "llm_generated" for s in suggestions)

    log.info("autofix.complete", suggestions=len(suggestions))

    return {
        **state,
        "autofix_suggestions": suggestions,
        "autofix_pr_possible": autofix_pr_possible,
    }


def _build_fix_prompt(finding: dict, patch: str) -> str:
    return (
        f"Vulnerability: {finding.get('vuln_type', '')}\n"
        f"CWE: {finding.get('cwe', 'N/A')}\n"
        f"Severity: {finding.get('severity', '')}\n"
        f"Description: {finding.get('description', '')}\n\n"
        f"File patch:\n```\n{patch[:4000]}\n```\n\n"
        "Provide a minimal, targeted fix in JSON: "
        '{"fixed_code": "...", "explanation": "..."}'
    )


def _extract_fix_code(response: str) -> str | None:
    import json, re
    try:
        m = re.search(r'"fixed_code"\s*:\s*"([^"]*)"', response, re.DOTALL)
        if m:
            return m.group(1).replace("\\n", "\n").replace('\\"', '"')
        # Try JSON parse
        data = json.loads(response)
        return data.get("fixed_code")
    except Exception:
        return None
