"""Bandit wrapper for changed Python files."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

from aegis.obs import get_logger
from aegis.schemas import FileChange, Finding, FindingSource, Severity

log = get_logger("aegis.bandit")

_SEV = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


async def run_bandit(
    file_texts: dict[str, str], changed: dict[str, FileChange]
) -> list[Finding]:
    python_files = {
        path: text for path, text in file_texts.items()
        if path.endswith(".py") and path in changed
    }
    if not python_files:
        return []

    with tempfile.TemporaryDirectory(prefix="aegis-bandit-") as tmp:
        root = Path(tmp)
        for path, text in python_files.items():
            dest = root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8", errors="replace")

        proc = await asyncio.create_subprocess_exec(
            "bandit",
            "-q",
            "-f",
            "json",
            "-r",
            str(root),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode not in (0, 1):  # 1 = findings present
            log.warning("bandit.failed", code=proc.returncode, err=err.decode()[:500])
            return []
        data = _parse_report(out)

    return _findings_from_report(data, root, changed)


def _findings_from_report(
    data: dict[str, Any],
    root: Path,
    changed: dict[str, FileChange],
) -> list[Finding]:
    findings: list[Finding] = []
    for item in data.get("results", []):
        filename = str(item.get("filename", ""))
        rel = filename.replace(f"{root}/", "")
        fc = changed.get(rel)
        if fc is None:
            continue
        line = int(item.get("line_number") or 0)
        added = {ln.new_lineno for ln in fc.added_lines() if ln.new_lineno is not None}
        if line not in added:
            continue
        pos = next((ln.diff_position for ln in fc.added_lines() if ln.new_lineno == line), None)
        test_id = str(item.get("test_id") or "bandit")
        severity = _SEV.get(str(item.get("issue_severity", "MEDIUM")).upper(), Severity.MEDIUM)
        findings.append(
            Finding(
                file=rel,
                line=line,
                diff_position=pos,
                cwe=_cwe_for(test_id),
                rule_id=f"bandit:{test_id}",
                severity=severity,
                confidence=0.90,
                source=FindingSource.DETERMINISTIC,
                title=str(item.get("test_name") or test_id),
                rationale=str(item.get("issue_text") or "")[:1200],
                exploit=str(item.get("more_info") or "") or None,
                fix="Replace the unsafe Python construct with a safe API and validate inputs.",
            )
        )
    return findings


def _parse_report(raw: bytes) -> dict[str, Any]:
    if not raw.strip():
        return {"results": []}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"results": []}
    return data if isinstance(data, dict) else {"results": []}


def _cwe_for(test_id: str) -> str | None:
    return {
        "B102": "CWE-94",   # exec
        "B307": "CWE-94",   # eval
        "B602": "CWE-78",   # subprocess shell=True
        "B608": "CWE-89",   # SQL injection
        "B506": "CWE-502",  # yaml load
    }.get(test_id)
