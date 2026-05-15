"""Semgrep SAST wrapper — runs semgrep CLI against a temp directory."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

from aegis.observability.logging import get_logger
from aegis.observability.metrics import scanner_duration_seconds, scanner_errors_total

log = get_logger(__name__)

_DEFAULT_RULES = ["p/default", "p/python", "p/javascript", "p/typescript", "p/security-audit"]


async def run_semgrep(
    files: list[dict[str, Any]],
    rules: list[str] | None = None,
    timeout: int = 120,
) -> list[dict[str, Any]]:
    """Run semgrep on given file patches and return normalized findings.

    Args:
        files: list of DiffFile dicts with 'filename' and 'patch' keys.
        rules: semgrep rule selectors (defaults to security pack).
        timeout: max seconds before killing semgrep.

    Returns:
        List of finding dicts with keys:
        {file_path, line_number, vuln_type, severity, description, cwe, source, fingerprint}
    """
    if not files:
        return []

    rules = rules or _DEFAULT_RULES

    with scanner_duration_seconds.labels("semgrep").time():
        with tempfile.TemporaryDirectory(prefix="aegis_semgrep_") as tmp:
            # Write patch content to temp files
            for f in files:
                path = Path(tmp) / f["filename"]
                path.parent.mkdir(parents=True, exist_ok=True)
                # Use patch lines as file content approximation
                code_lines = _extract_added_lines(f.get("patch", ""))
                path.write_text(code_lines, encoding="utf-8")

            rule_args = []
            for r in rules:
                rule_args.extend(["--config", r])

            cmd = [
                "semgrep",
                *rule_args,
                "--json",
                "--no-git-ignore",
                "--timeout", str(timeout),
                "--quiet",
                tmp,
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 10)
            except asyncio.TimeoutError:
                scanner_errors_total.labels("semgrep").inc()
                log.warning("semgrep.timeout")
                return []
            except FileNotFoundError:
                log.warning("semgrep.not_installed")
                return []

            if proc.returncode not in (0, 1):  # 1 = findings found, still OK
                scanner_errors_total.labels("semgrep").inc()
                log.warning("semgrep.error", stderr=stderr.decode()[:500])
                return []

            try:
                data = json.loads(stdout.decode())
            except json.JSONDecodeError:
                return []

            findings: list[dict[str, Any]] = []
            for result in data.get("results", []):
                meta = result.get("extra", {})
                findings.append(
                    {
                        "file_path": result.get("path", "").replace(tmp, "").lstrip("/\\"),
                        "line_number": result.get("start", {}).get("line"),
                        "vuln_type": result.get("check_id", ""),
                        "severity": _map_severity(meta.get("severity", "WARNING")),
                        "description": meta.get("message", ""),
                        "cwe": _extract_cwe(meta.get("metadata", {})),
                        "source": "semgrep",
                        "fingerprint": result.get("extra", {}).get("fingerprint", ""),
                        "confidence": 0.9,
                        "fix_snippet": meta.get("fix", None),
                    }
                )
            log.info("semgrep.done", findings=len(findings))
            return findings


def _extract_added_lines(patch: str) -> str:
    """Extract only '+' lines from a unified diff patch."""
    lines = []
    for line in patch.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
    return "\n".join(lines)


def _map_severity(semgrep_severity: str) -> str:
    return {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
        "CRITICAL": "critical",
    }.get(semgrep_severity.upper(), "medium")


def _extract_cwe(metadata: dict) -> str | None:
    cwe = metadata.get("cwe") or metadata.get("CWE")
    if isinstance(cwe, list):
        return cwe[0] if cwe else None
    return cwe
