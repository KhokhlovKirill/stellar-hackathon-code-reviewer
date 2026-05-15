"""LLM parser/prompt unit tests; no network calls."""

from __future__ import annotations

import json

from aegis.llm.parser import _normalise_finding, finding_schema, parse_findings
from aegis.llm.prompt import review_messages
from aegis.schemas import (
    DiffLine,
    FileChange,
    FindingSource,
    Hunk,
    LineKind,
)


def _file() -> FileChange:
    return FileChange(
        path="app/db.py",
        status="modified",
        language="python",
        hunks=[
            Hunk(
                old_start=1,
                old_count=1,
                new_start=1,
                new_count=2,
                header="@@ -1,1 +1,2 @@",
                lines=[
                    DiffLine(
                        kind=LineKind.ADD,
                        content="q = 'select ' + uid",
                        new_lineno=7,
                        diff_position=3,
                    ),
                    DiffLine(
                        kind=LineKind.CTX,
                        content="return db.query(q)",
                        new_lineno=8,
                        old_lineno=2,
                    ),
                ],
            )
        ],
    )


def test_finding_schema_has_strict_envelope() -> None:
    schema = finding_schema()
    assert schema["required"] == ["findings"]
    assert schema["additionalProperties"] is False


def test_parse_findings_keeps_only_changed_lines() -> None:
    content = json.dumps({
        "findings": [
            {
                "file": "app/db.py",
                "line": 7,
                "cwe": "CWE-89",
                "severity": "critical",
                "confidence": 0.91,
                "title": "SQL injection",
                "rationale": "uid is concatenated into SQL",
                "exploit": "uid=1 OR 1=1",
                "fix": "use parameterized query",
            },
            {
                "file": "app/db.py",
                "line": 8,
                "cwe": "CWE-89",
                "severity": "critical",
                "confidence": 0.91,
                "title": "Unchanged line",
                "rationale": "not on added line",
                "exploit": None,
                "fix": None,
            },
        ]
    })
    parsed = parse_findings(
        content,
        source=FindingSource.LLM_A,
        changed_lines={"app/db.py": {7}},
        diff_positions={("app/db.py", 7): 3},
    )
    assert len(parsed) == 1
    assert parsed[0].line == 7
    assert parsed[0].diff_position == 3


def test_normalise_finding_don_agent_v3_format() -> None:
    """don-agent-v3 native schema is mapped to Aegis canonical schema."""
    raw = {
        "file": "auth/login.py",
        "line_number": 12,
        "cwe": 89,
        "severity": "high",
        "confidence": "high",
        "title": "SQL Injection",
        "description": "User input concatenated into SQL.",
        "impact": "Auth bypass possible.",
        "code_snippet": "query = f\"SELECT * FROM users WHERE id = '{uid}'\"",
        "remediation": "Use parameterized queries.",
    }
    out = _normalise_finding(raw)
    assert out["line"] == 12
    assert out["cwe"] == "CWE-89"
    assert isinstance(out["confidence"], float)
    assert out["confidence"] == 0.85
    assert "concatenated" in out["rationale"]
    assert out["exploit"] is not None and "SELECT" in out["exploit"]
    assert out["fix"] is not None and "parameterized" in out["fix"]
    assert "line_number" not in out


def test_normalise_finding_string_cwe_passthrough() -> None:
    raw = {
        "file": "x.py", "line": 5,
        "cwe": "CWE-798", "severity": "critical",
        "confidence": 0.9, "title": "secret",
        "rationale": "hardcoded", "exploit": None, "fix": None,
    }
    out = _normalise_finding(raw)
    assert out["cwe"] == "CWE-798"
    assert out["confidence"] == 0.9


def test_parse_findings_accepts_don_agent_native() -> None:
    """parse_findings handles don-agent-v3 output without crashing."""
    content = json.dumps({
        "findings": [
            {
                "file": "app/db.py",
                "line_number": 7,
                "cwe": 89,
                "severity": "high",
                "confidence": "high",
                "title": "SQL injection",
                "description": "concat",
                "impact": "bypass",
                "code_snippet": "x + sql",
                "remediation": "use params",
            }
        ]
    })
    parsed = parse_findings(
        content,
        source=FindingSource.LLM_A,
        changed_lines={"app/db.py": {7}},
        diff_positions={("app/db.py", 7): 3},
    )
    assert len(parsed) == 1
    assert parsed[0].line == 7
    assert parsed[0].cwe == "CWE-89"
    assert parsed[0].confidence == 0.85


def test_review_prompt_marks_diff_as_untrusted_data() -> None:
    messages = review_messages(
        repo="o/r",
        pr_id="12",
        files=[_file()],
        deterministic_findings=[],
        context_map={"app/db.py": "@@ context app/db.py:1-2 @@\n1: def f(): pass"},
    )
    assert "untrusted data" in messages[0]["content"]
    assert "<<<DIFF>>>" in messages[1]["content"]
    assert "<<<CONTEXT>>>" in messages[1]["content"]
    assert "context app/db.py" in messages[1]["content"]
    assert "new=7" in messages[1]["content"]
