<<<<<<< Updated upstream
"""Bandit wrapper for changed Python files."""
=======
"""Bandit SAST wrapper for Python files."""
>>>>>>> Stashed changes

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

<<<<<<< Updated upstream
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
=======
from aegis.observability.logging import get_logger
from aegis.observability.metrics import scanner_duration_seconds, scanner_errors_total

log = get_logger(__name__)


async def run_bandit(
    files: list[dict[str, Any]],
    timeout: int = 60,
) -> list[dict[str, Any]]:
    """Run bandit on Python files only.

    Filters incoming files to .py only before scanning.
    """
    python_files = [f for f in files if f["filename"].endswith(".py")]
    if not python_files:
        return []

    with scanner_duration_seconds.labels("bandit").time():
        with tempfile.TemporaryDirectory(prefix="aegis_bandit_") as tmp:
            for f in python_files:
                path = Path(tmp) / f["filename"]
                path.parent.mkdir(parents=True, exist_ok=True)
                code = _extract_added_lines(f.get("patch", ""))
                path.write_text(code, encoding="utf-8")

            cmd = [
                "bandit",
                "-r", tmp,
                "-f", "json",
                "--quiet",
                "--severity-level", "medium",
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                scanner_errors_total.labels("bandit").inc()
                log.warning("bandit.timeout")
                return []
            except FileNotFoundError:
                log.warning("bandit.not_installed")
                return []

            try:
                data = json.loads(stdout.decode())
            except json.JSONDecodeError:
                return []

            findings: list[dict[str, Any]] = []
            for result in data.get("results", []):
                findings.append(
                    {
                        "file_path": result.get("filename", "").replace(tmp, "").lstrip("/\\"),
                        "line_number": result.get("line_number"),
                        "vuln_type": result.get("test_id", ""),
                        "severity": result.get("issue_severity", "medium").lower(),
                        "description": result.get("issue_text", ""),
                        "cwe": result.get("issue_cwe", {}).get("id"),
                        "source": "bandit",
                        "confidence": _bandit_confidence(result.get("issue_confidence", "MEDIUM")),
                        "fingerprint": f"bandit:{result.get('test_id')}:{result.get('filename')}:{result.get('line_number')}",
                    }
                )
            log.info("bandit.done", findings=len(findings), python_files=len(python_files))
            return findings


def _extract_added_lines(patch: str) -> str:
    lines = []
    for line in patch.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
    return "\n".join(lines)


def _bandit_confidence(confidence: str) -> float:
    return {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}.get(confidence.upper(), 0.7)
>>>>>>> Stashed changes
