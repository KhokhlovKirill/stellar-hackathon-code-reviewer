<<<<<<< Updated upstream
"""Semgrep OSS wrapper (criterion C3).

Semgrep needs whole files for accurate taint analysis, so we analyze the full
content of *changed* files (never the whole repo) and then keep only findings
whose line falls on an added line — exactly the changed-lines contract (docs/05
§1.2). Rulesets are vendored into the image at build (offline at scan time).
"""
=======
"""Semgrep SAST wrapper — runs semgrep CLI against a temp directory."""
>>>>>>> Stashed changes

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

<<<<<<< Updated upstream
from aegis.config import get_config
from aegis.obs import get_logger
from aegis.schemas import FileChange, Finding, FindingSource, Severity

log = get_logger("aegis.semgrep")

_SEV = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def _added_line_set(fc: FileChange) -> set[int]:
    return {ln.new_lineno for ln in fc.added_lines() if ln.new_lineno is not None}


def _position_for(fc: FileChange, line: int) -> int | None:
    for ln in fc.added_lines():
        if ln.new_lineno == line:
            return ln.diff_position
    return None


def _cwe_from(meta: dict[str, Any]) -> str | None:
    cwe = meta.get("cwe")
    if isinstance(cwe, list) and cwe:
        cwe = cwe[0]
    if isinstance(cwe, str):
        token = cwe.split(":")[0].strip()
        return token if token.upper().startswith("CWE-") else None
    return None


async def run_semgrep(
    file_texts: dict[str, str], changed: dict[str, FileChange]
) -> list[Finding]:
    """`file_texts`: path -> full current content of changed code files."""
    if not file_texts:
        return []
    cfg = get_config().deterministic
    findings: list[Finding] = []

    with tempfile.TemporaryDirectory(prefix="aegis-sg-") as tmp:
        root = Path(tmp)
        for path, text in file_texts.items():
            dest = root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8", errors="replace")

        cmd = ["semgrep", "scan", "--json", "--quiet", "--no-git-ignore", "--metrics=off"]
        for c in cfg.semgrep_configs:
            cmd += ["--config", c]
        cmd.append(str(root))

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, err = await proc.communicate()
        if proc.returncode not in (0, 1):  # 1 = findings present
            log.warning("semgrep.failed", code=proc.returncode, err=err.decode()[:500])
            return []
        try:
            data = json.loads(out or b"{}")
        except json.JSONDecodeError:
            log.warning("semgrep.bad_json")
            return []

    for res in data.get("results", []):
        rel = str(Path(res["path"]).relative_to(root)) if str(res["path"]).startswith(
            str(root)
        ) else res["path"].replace(f"{root}/", "")
        fc = changed.get(rel)
        if fc is None:
            continue
        line = res.get("start", {}).get("line")
        if line is None or line not in _added_line_set(fc):
            continue  # finding not on a changed line -> ignore (changed-lines contract)
        extra = res.get("extra", {})
        meta = extra.get("metadata", {})
        sev = _SEV.get(extra.get("severity", "WARNING"), Severity.MEDIUM)
        msg = extra.get("message", res.get("check_id", "semgrep finding"))
        findings.append(Finding(
            file=rel, line=line, diff_position=_position_for(fc, line),
            cwe=_cwe_from(meta), rule_id=res.get("check_id"),
            severity=sev, confidence=0.95, source=FindingSource.DETERMINISTIC,
            title=(meta.get("shortDescription") or res.get("check_id", "")).split("\n")[0][:160],
            rationale=msg.strip()[:1200],
            exploit=(meta.get("references") or [None])[0],
            fix=(extra.get("fix") or None),
            fix_is_suggestion=bool(extra.get("fix")),
        ))
    return findings
=======
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
>>>>>>> Stashed changes
