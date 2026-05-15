"""Gitleaks wrapper over added lines only.

We materialize one temporary file per changed file containing only added lines,
run `gitleaks detect --no-git --report-format json`, then map temporary line
numbers back to right-side diff lines. If the binary is not installed the caller
gets FileNotFoundError and can mark degraded.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

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
