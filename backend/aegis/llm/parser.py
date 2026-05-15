"""Parse and validate LLM JSON findings.

Handles two schemas:
- Aegis canonical: {file, line, cwe, severity, confidence, title, rationale, exploit, fix}
- don-agent-v3 native: {file, line_number, cwe (int), severity, confidence (str),
    title, description, impact, code_snippet, remediation}

Both are normalised into Finding objects. The normaliser runs before Pydantic
validation so downstream is always canonical.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from aegis.schemas import Finding, FindingSource, Severity

_CONFIDENCE_MAP = {"low": 0.45, "medium": 0.65, "high": 0.85, "very high": 0.95}


def _normalise_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Map don-agent-v3 native fields to the canonical Aegis schema."""
    out = dict(raw)

    # line_number → line
    if "line" not in out and "line_number" in out:
        out["line"] = out.pop("line_number")

    # cwe: int → "CWE-N" string
    cwe = out.get("cwe")
    if isinstance(cwe, int):
        out["cwe"] = f"CWE-{cwe}"
    elif isinstance(cwe, str) and cwe.isdigit():
        out["cwe"] = f"CWE-{cwe}"

    # confidence: string label → float
    conf = out.get("confidence")
    if isinstance(conf, str):
        out["confidence"] = _CONFIDENCE_MAP.get(conf.lower().strip(), 0.7)

    # rationale: merge description + impact
    if "rationale" not in out or not out["rationale"]:
        parts = [out.pop("description", ""), out.pop("impact", "")]
        out["rationale"] = " ".join(p for p in parts if p).strip() or "no rationale"
    else:
        out.pop("description", None)
        out.pop("impact", None)

    # exploit: code_snippet
    if "exploit" not in out or not out["exploit"]:
        out["exploit"] = out.pop("code_snippet", None)
    else:
        out.pop("code_snippet", None)

    # fix: remediation
    if "fix" not in out or not out["fix"]:
        out["fix"] = out.pop("remediation", None)
    else:
        out.pop("remediation", None)

    return out


class _LLMFinding(BaseModel):
    file: str
    line: int
    cwe: str | None = None
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    rationale: str
    exploit: str | None = None
    fix: str | None = None


class _LLMEnvelope(BaseModel):
    findings: list[_LLMFinding] = Field(default_factory=list)


def finding_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "file": {"type": "string"},
                        "line": {"type": "integer"},
                        "cwe": {"type": ["string", "null"]},
                        "severity": {
                            "type": "string",
                            "enum": ["info", "low", "medium", "high", "critical"],
                        },
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "title": {"type": "string"},
                        "rationale": {"type": "string"},
                        "exploit": {"type": ["string", "null"]},
                        "fix": {"type": ["string", "null"]},
                    },
                    "required": [
                        "file",
                        "line",
                        "cwe",
                        "severity",
                        "confidence",
                        "title",
                        "rationale",
                        "exploit",
                        "fix",
                    ],
                },
            }
        },
        "required": ["findings"],
    }


def parse_findings(
    content: str,
    *,
    source: FindingSource,
    changed_lines: dict[str, set[int]] | None = None,
    diff_positions: dict[tuple[str, int], int | None] | None = None,
) -> list[Finding]:
    raw = _json_object(content)
    # Normalise each finding (handles don-agent-v3 native schema)
    normalised_items = [_normalise_finding(item) for item in raw.get("findings", [])]
    try:
        env = _LLMEnvelope.model_validate({"findings": normalised_items})
    except ValidationError:
        return []

    out: list[Finding] = []
    for f in env.findings:
        # When changed_lines is provided (webhook pipeline), filter to diff lines only
        if changed_lines is not None and f.line not in changed_lines.get(f.file, set()):
            continue
        out.append(Finding(
            file=f.file,
            line=f.line,
            diff_position=diff_positions.get((f.file, f.line)) if diff_positions else None,
            cwe=f.cwe,
            rule_id=f"llm:{source.value}",
            severity=f.severity,
            confidence=f.confidence,
            source=source,
            title=f.title[:180],
            rationale=f.rationale[:1800],
            exploit=f.exploit[:1200] if f.exploit else None,
            fix=f.fix[:2000] if f.fix else None,
            fix_is_suggestion=bool(f.fix),
        ))
    return out


def _json_object(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            return {"findings": []}
        try:
            data = json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return {"findings": []}
    return data if isinstance(data, dict) else {"findings": []}
