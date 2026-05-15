"""Gitleaks secret scanner wrapper."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

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
