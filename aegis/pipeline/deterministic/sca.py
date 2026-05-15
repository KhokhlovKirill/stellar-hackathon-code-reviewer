"""Software Composition Analysis — checks manifests against OSV API."""

from __future__ import annotations

import json
from typing import Any

import httpx

from aegis.observability.logging import get_logger
from aegis.observability.metrics import scanner_duration_seconds, scanner_errors_total

log = get_logger(__name__)

_OSV_API = "https://api.osv.dev/v1/querybatch"

_MANIFEST_FILES = {
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "Pipfile.lock", "poetry.lock",
    "package.json", "package-lock.json", "yarn.lock",
    "pom.xml", "build.gradle",
    "Gemfile.lock",
    "Cargo.lock",
    "go.sum",
}


async def run_sca(
    manifest_files: list[dict[str, Any]],
    timeout: int = 60,
) -> list[dict[str, Any]]:
    """Check manifest files for known-vulnerable dependencies via OSV API.

    Args:
        manifest_files: DiffFile dicts where filename matches _MANIFEST_FILES.
        timeout: HTTP timeout in seconds.

    Returns:
        List of vulnerability findings with package info.
    """
    if not manifest_files:
        return []

    packages = _extract_packages(manifest_files)
    if not packages:
        return []

    log.info("sca.start", packages=len(packages))

    with scanner_duration_seconds.labels("sca").time():
        queries = [
            {"package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]},
             "version": pkg["version"]}
            for pkg in packages
        ]

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(_OSV_API, json={"queries": queries})
                r.raise_for_status()
                data = r.json()
        except Exception as exc:
            scanner_errors_total.labels("sca").inc()
            log.warning("sca.api_error", error=str(exc))
            return []

    findings: list[dict[str, Any]] = []
    for i, result in enumerate(data.get("results", [])):
        vulns = result.get("vulns", [])
        if not vulns:
            continue
        pkg = packages[i] if i < len(packages) else {}
        for vuln in vulns[:5]:  # cap per package
            severity = _osv_severity(vuln)
            findings.append(
                {
                    "file_path": pkg.get("source_file", "manifest"),
                    "line_number": pkg.get("line_number"),
                    "vuln_type": "vulnerable-dependency",
                    "severity": severity,
                    "description": (
                        f"Package {pkg.get('name')} {pkg.get('version')} is vulnerable: "
                        f"{vuln.get('id')} — {vuln.get('summary', '')[:200]}"
                    ),
                    "cwe": None,
                    "source": "sca",
                    "confidence": 1.0,
                    "fingerprint": f"sca:{pkg.get('name')}:{vuln.get('id')}",
                    "fix_snippet": _suggest_fix(vuln),
                }
            )

    log.info("sca.done", packages=len(packages), findings=len(findings))
    return findings


def _extract_packages(manifest_files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Parse manifest file patches to extract package+version pairs."""
    packages: list[dict[str, Any]] = []

    for f in manifest_files:
        fname = f.get("filename", "")
        patch = f.get("patch", "")
        added_lines = [
            line[1:] for line in patch.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]

        if "requirements" in fname and fname.endswith(".txt"):
            for line in added_lines:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-r"):
                    continue
                for sep in ("==", ">=", "<=", "~=", "!="):
                    if sep in line:
                        name, version = line.split(sep, 1)
                        packages.append({
                            "name": name.strip().lower(),
                            "version": version.strip().split(",")[0],
                            "ecosystem": "PyPI",
                            "source_file": fname,
                        })
                        break

        elif fname == "package.json":
            import re
            for line in added_lines:
                m = re.search(r'"([a-zA-Z@][^"]*)":\s*"(\^|~|)?(\d[\d.]*)', line)
                if m:
                    packages.append({
                        "name": m.group(1),
                        "version": m.group(3),
                        "ecosystem": "npm",
                        "source_file": fname,
                    })

    return packages


def _osv_severity(vuln: dict) -> str:
    severity = "medium"
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        try:
            score = float(score_str)
            if score >= 9.0:
                severity = "critical"
            elif score >= 7.0:
                severity = "high"
            elif score >= 4.0:
                severity = "medium"
            else:
                severity = "low"
        except (ValueError, TypeError):
            pass
    return severity


def _suggest_fix(vuln: dict) -> str | None:
    affected = vuln.get("affected", [])
    for pkg in affected:
        ranges = pkg.get("ranges", [])
        for r in ranges:
            events = r.get("events", [])
            for evt in events:
                fixed = evt.get("fixed")
                if fixed:
                    return f"Обновить до версии >= {fixed}"
    return None
