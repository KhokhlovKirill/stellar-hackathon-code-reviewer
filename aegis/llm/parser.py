"""Parse and validate LLM JSON findings."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from aegis.schemas import Finding, FindingSource, Severity


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
    changed_lines: dict[str, set[int]],
    diff_positions: dict[tuple[str, int], int | None],
) -> list[Finding]:
    raw = _json_object(content)
    try:
        env = _LLMEnvelope.model_validate(raw)
    except ValidationError:
        return []

    out: list[Finding] = []
    for f in env.findings:
        if f.line not in changed_lines.get(f.file, set()):
            continue
        out.append(Finding(
            file=f.file,
            line=f.line,
            diff_position=diff_positions.get((f.file, f.line)),
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
