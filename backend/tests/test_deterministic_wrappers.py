"""Parser/mapping units for optional deterministic CLI wrappers."""

from __future__ import annotations

import json
from pathlib import Path

from aegis.pipeline.deterministic.bandit import _findings_from_report
from aegis.pipeline.deterministic.gitleaks import _materialize_added_lines, _parse_report
from aegis.schemas import DiffLine, FileChange, Hunk, LineKind


def _file() -> FileChange:
    return FileChange(
        path="app/vuln.py",
        status="modified",
        language="python",
        hunks=[
            Hunk(
                old_start=1,
                old_count=1,
                new_start=10,
                new_count=2,
                header="@@ -1,1 +10,2 @@",
                lines=[
                    DiffLine(
                        kind=LineKind.ADD,
                        content="eval(user)",
                        new_lineno=10,
                        diff_position=4,
                    ),
                    DiffLine(
                        kind=LineKind.ADD,
                        content="password = 'abc123ABC123abc123ABC123'",
                        new_lineno=11,
                        diff_position=5,
                    ),
                ],
            )
        ],
    )


def test_gitleaks_materializes_added_lines_with_real_mapping() -> None:
    added = _materialize_added_lines([_file()])
    assert added["app/vuln.py"][0] == (10, 4, "eval(user)")
    assert added["app/vuln.py"][1][0] == 11


def test_gitleaks_parse_report_rejects_bad_json() -> None:
    assert _parse_report(b"not-json") == []
    assert _parse_report(json.dumps([{"RuleID": "generic-api-key"}]).encode())[0]["RuleID"]


def test_bandit_report_filters_to_added_lines_and_maps_cwe() -> None:
    root = Path("/tmp/aegis-bandit-test")
    data = {
        "results": [
            {
                "filename": str(root / "app/vuln.py"),
                "line_number": 10,
                "test_id": "B307",
                "test_name": "blacklist",
                "issue_severity": "HIGH",
                "issue_text": "Use of possibly insecure function",
            },
            {
                "filename": str(root / "app/vuln.py"),
                "line_number": 9,
                "test_id": "B307",
                "test_name": "unchanged",
                "issue_severity": "HIGH",
                "issue_text": "should be ignored",
            },
        ]
    }
    findings = _findings_from_report(data, root, {"app/vuln.py": _file()})
    assert len(findings) == 1
    assert findings[0].line == 10
    assert findings[0].diff_position == 4
    assert findings[0].cwe == "CWE-94"
