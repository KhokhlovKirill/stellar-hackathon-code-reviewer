"""Bandit SAST wrapper for Python files."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

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
