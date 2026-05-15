<<<<<<< Updated upstream
"""Gitleaks wrapper over added lines only.

We materialize one temporary file per changed file containing only added lines,
run `gitleaks detect --no-git --report-format json`, then map temporary line
numbers back to right-side diff lines. If the binary is not installed the caller
gets FileNotFoundError and can mark degraded.
"""
=======
"""Gitleaks secret scanner wrapper."""
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

log = get_logger("aegis.gitleaks")


async def run_gitleaks(files: list[FileChange]) -> list[Finding]:
    added = _materialize_added_lines(files)
    if not added:
        return []

    findings: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="aegis-gitleaks-") as tmp:
        root = Path(tmp)
        line_map: dict[tuple[str, int], tuple[str, int, int | None]] = {}
        for path, lines in added.items():
            dest = root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text("\n".join(content for _line, _pos, content in lines), encoding="utf-8")
            for temp_lineno, (real_lineno, diff_pos, _content) in enumerate(lines, start=1):
                rel = str(dest.relative_to(root))
                line_map[(rel, temp_lineno)] = (path, real_lineno, diff_pos)

        proc = await asyncio.create_subprocess_exec(
            "gitleaks",
            "detect",
            "--no-git",
            "--source",
            str(root),
            "--report-format",
            "json",
            "--redact",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode not in (0, 1):  # 1 = leaks found
            log.warning("gitleaks.failed", code=proc.returncode, err=err.decode()[:500])
            return []
        data = _parse_report(out)

    for item in data:
        rel = str(item.get("File", ""))
        temp_line = int(item.get("StartLine") or item.get("Line") or 0)
        mapped = line_map.get((rel, temp_line))
        if mapped is None:
            continue
        path, line, diff_pos = mapped
        rule = str(item.get("RuleID") or item.get("Description") or "gitleaks")
        findings.append(
            Finding(
                file=path,
                line=line,
                diff_position=diff_pos,
                cwe="CWE-798",
                rule_id=f"gitleaks:{rule}",
                severity=Severity.CRITICAL,
                confidence=0.99,
                source=FindingSource.DETERMINISTIC,
                title=f"Secret detected by Gitleaks: {rule}",
                rationale="Gitleaks detected a credential pattern on an added line.",
                exploit="Anyone with repository history access can recover the committed secret.",
                fix=(
                    "Remove the secret, rotate it, and load it from a secret manager "
                    "or environment."
                ),
            )
        )
    return findings


def _materialize_added_lines(
    files: list[FileChange],
) -> dict[str, list[tuple[int, int | None, str]]]:
    out: dict[str, list[tuple[int, int | None, str]]] = {}
    for fc in files:
        lines = [
            (ln.new_lineno, ln.diff_position, ln.content)
            for ln in fc.added_lines()
            if ln.new_lineno is not None
        ]
        if lines:
            out[fc.path] = [(int(line), pos, content) for line, pos, content in lines]
    return out


def _parse_report(raw: bytes) -> list[dict[str, Any]]:
    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []
=======
from aegis.observability.logging import get_logger
from aegis.observability.metrics import scanner_duration_seconds, scanner_errors_total

log = get_logger(__name__)


async def run_gitleaks(
    files: list[dict[str, Any]],
    diff: str = "",
    timeout: int = 60,
) -> list[dict[str, Any]]:
    """Run gitleaks on a unified diff to detect leaked secrets.

    Writes the full diff to a temp file and scans with `gitleaks detect`.
    """
    if not diff and not files:
        return []

    diff_content = diff or _build_diff_from_files(files)

    with scanner_duration_seconds.labels("gitleaks").time():
        with tempfile.TemporaryDirectory(prefix="aegis_gitleaks_") as tmp:
            diff_file = Path(tmp) / "pr.diff"
            diff_file.write_text(diff_content, encoding="utf-8")

            report_file = Path(tmp) / "report.json"

            cmd = [
                "gitleaks",
                "detect",
                "--source", diff_file.as_posix(),
                "--no-git",
                "--report-format", "json",
                "--report-path", report_file.as_posix(),
                "--exit-code", "0",
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                scanner_errors_total.labels("gitleaks").inc()
                log.warning("gitleaks.timeout")
                return []
            except FileNotFoundError:
                log.warning("gitleaks.not_installed")
                return _run_regex_fallback(diff_content)

            if not report_file.exists():
                return []

            try:
                leaks = json.loads(report_file.read_text())
            except json.JSONDecodeError:
                return []

            findings: list[dict[str, Any]] = []
            for leak in leaks:
                findings.append(
                    {
                        "file_path": leak.get("File", ""),
                        "line_number": leak.get("StartLine"),
                        "vuln_type": leak.get("RuleID", "secret"),
                        "severity": "critical",
                        "description": f"Secret detected: {leak.get('Description', 'possible credential')}",
                        "cwe": "CWE-798",
                        "source": "gitleaks",
                        "confidence": 0.95,
                        "fingerprint": leak.get("Fingerprint", ""),
                        "match_snippet": leak.get("Match", "")[:80],
                    }
                )
            log.info("gitleaks.done", findings=len(findings))
            return findings


def _build_diff_from_files(files: list[dict[str, Any]]) -> str:
    parts = []
    for f in files:
        parts.append(f"--- a/{f['filename']}\n+++ b/{f['filename']}\n{f.get('patch', '')}")
    return "\n".join(parts)


import re as _re

_SECRET_PATTERNS = [
    (_re.compile(r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]"), "hardcoded-password"),
    (_re.compile(r"(?i)(api_?key|apikey)\s*=\s*['\"][^'\"]{16,}['\"]"), "hardcoded-api-key"),
    (_re.compile(r"(?i)(secret|token)\s*=\s*['\"][^'\"]{16,}['\"]"), "hardcoded-secret"),
    (_re.compile(r"sk-[a-zA-Z0-9]{40,}"), "openai-api-key"),
    (_re.compile(r"AKIA[0-9A-Z]{16}"), "aws-access-key"),
    (_re.compile(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"), "private-key"),
]


def _run_regex_fallback(diff: str) -> list[dict[str, Any]]:
    """Very basic regex fallback when gitleaks is not installed."""
    findings = []
    for line_no, line in enumerate(diff.splitlines(), 1):
        if not line.startswith("+"):
            continue
        for pattern, vuln_type in _SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    {
                        "file_path": "unknown",
                        "line_number": line_no,
                        "vuln_type": vuln_type,
                        "severity": "critical",
                        "description": f"Potential {vuln_type} in diff",
                        "cwe": "CWE-798",
                        "source": "gitleaks_regex",
                        "confidence": 0.7,
                        "fingerprint": f"regex:{vuln_type}:{line_no}",
                    }
                )
                break
    return findings
>>>>>>> Stashed changes
