"""Parse and validate JSON findings returned by LLM agents."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from aegis.observability.logging import get_logger

log = get_logger(__name__)

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_STATUSES = {"confirmed", "dismissed", "severity_adjusted"}


def extract_json_from_response(text: str) -> dict | list | None:
    """Extract the first valid JSON object or array from LLM response text."""
    # Try direct parse first
    stripped = text.strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    # Try to find JSON block in markdown code fence
    fence_match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\}|\[[\s\S]*?\])\s*```", stripped)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try to find first { ... } or [ ... ] in the text
    brace_match = re.search(r"(\{[\s\S]*\}|\[[\s\S]*\])", stripped)
    if brace_match:
        try:
            return json.loads(brace_match.group(1))
        except json.JSONDecodeError:
            pass

    log.warning("parse.json_extraction_failed", preview=text[:200])
    return None


def parse_llm_a_findings(response_text: str) -> list[dict[str, Any]]:
    """Parse Agent A response into a list of normalized findings."""
    data = extract_json_from_response(response_text)
    if not data or not isinstance(data, dict):
        return []

    raw_findings = data.get("findings", [])
    return [_normalize_finding(f, source="llm_a") for f in raw_findings if isinstance(f, dict)]


def parse_llm_b_findings(response_text: str) -> tuple[list[dict], bool]:
    """Parse Agent B response into validated + new findings.

    Returns:
        (merged_findings_list, requires_human_review)
    """
    data = extract_json_from_response(response_text)
    if not data or not isinstance(data, dict):
        return [], False

    findings: list[dict] = []
    for f in data.get("validated_findings", []):
        if isinstance(f, dict) and f.get("status") != "dismissed":
            findings.append(_normalize_finding(f, source="llm_b"))
    for f in data.get("new_findings", []):
        if isinstance(f, dict):
            findings.append(_normalize_finding(f, source="llm_b"))

    return findings, bool(data.get("requires_human_review", False))


def parse_judge_findings(response_text: str) -> tuple[list[dict], int, str, bool]:
    """Parse Judge response.

    Returns:
        (final_findings, risk_score, risk_label, requires_human_review)
    """
    data = extract_json_from_response(response_text)
    if not data or not isinstance(data, dict):
        return [], 0, "green", False

    final_findings = [
        _normalize_finding(f, source="judge")
        for f in data.get("final_findings", [])
        if isinstance(f, dict)
    ]
    risk_score = min(100, max(0, int(data.get("risk_score", 0))))
    risk_label = data.get("risk_label", "green")
    requires_human_review = bool(data.get("requires_human_review", False))

    return final_findings, risk_score, risk_label, requires_human_review


def _normalize_finding(f: dict[str, Any], source: str = "llm") -> dict[str, Any]:
    """Normalize a raw finding dict to the standard schema."""
    severity = f.get("severity", "medium").lower()
    if severity not in _VALID_SEVERITIES:
        severity = "medium"

    # Generate fingerprint if not present
    fingerprint = f.get("fingerprint") or _generate_fingerprint(
        f.get("file_path", ""),
        f.get("line_number"),
        f.get("vuln_type", ""),
    )

    confidence = float(f.get("confidence", 0.75))
    confidence = max(0.0, min(1.0, confidence))

    return {
        "file_path": f.get("file_path", ""),
        "line_number": f.get("line_number"),
        "end_line_number": f.get("end_line_number"),
        "vuln_type": f.get("vuln_type", ""),
        "cwe": f.get("cwe"),
        "severity": severity,
        "confidence": confidence,
        "description": f.get("description", ""),
        "fix_snippet": f.get("fix_snippet") or f.get("fixed_snippet"),
        "source": source,
        "fingerprint": fingerprint,
        "exploitability": f.get("exploitability", "medium"),
        "references": f.get("references", []),
    }


def _generate_fingerprint(file_path: str, line_number: Any, vuln_type: str) -> str:
    key = f"{file_path}:{line_number}:{vuln_type}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]
