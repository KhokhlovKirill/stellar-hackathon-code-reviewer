<<<<<<< Updated upstream
"""Software-composition analysis on changed dependency manifests (criterion C3 +
the supply-chain differentiator from task.md).

Parses added/changed dependency lines, queries OSV.dev (batch) for known
vulnerabilities / withdrawn versions, and emits findings with a concrete upgrade
recommendation. Network egress is limited to the configured allowlist (docs/10);
any failure degrades to "no SCA finding" rather than blocking the scan.
"""

from __future__ import annotations

import re

import httpx

from aegis.obs import get_logger
from aegis.schemas import FileChange, Finding, FindingSource, Severity

log = get_logger("aegis.sca")
_OSV_BATCH = "https://api.osv.dev/v1/querybatch"
_OSV_VULN = "https://api.osv.dev/v1/vulns/"

# (ecosystem, regex over an added manifest line -> name, version)
_REQ_TXT = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.\-]*)")
_PKG_JSON = re.compile(r'"\s*([@A-Za-z0-9_./\-]+)\s*"\s*:\s*"\s*[~^]?v?([0-9][\w.\-]*)')
_GO_MOD = re.compile(r"^\s*([A-Za-z0-9_./\-]+)\s+v([0-9][\w.\-]+)")


def _ecosystem(path: str) -> str | None:
    p = path.lower()
    if p.endswith(("requirements.txt", ".txt")) or "requirements" in p or p.endswith(
        ("pyproject.toml", "poetry.lock")
    ):
        return "PyPI"
    if p.endswith(("package.json", "package-lock.json", "yarn.lock")):
        return "npm"
    if p.endswith(("go.mod", "go.sum")):
        return "Go"
    return None


def _parse(path: str, fc: FileChange) -> list[tuple[str, str, str, int, int | None]]:
    eco = _ecosystem(path)
    if not eco:
        return []
    out: list[tuple[str, str, str, int, int | None]] = []
    for ln in fc.added_lines():
        if ln.new_lineno is None:
            continue
        text = ln.content
        m = None
        if eco == "PyPI":
            m = _REQ_TXT.search(text)
        elif eco == "npm":
            m = _PKG_JSON.search(text)
        elif eco == "Go":
            m = _GO_MOD.search(text)
        if m:
            out.append((eco, m.group(1), m.group(2), ln.new_lineno, ln.diff_position))
    return out


async def run_sca(manifests: list[FileChange]) -> list[Finding]:
    deps: list[tuple[str, str, str, int, int | None, str]] = []
    for fc in manifests:
        for eco, name, ver, line, pos in _parse(fc.path, fc):
            deps.append((eco, name, ver, line, pos, fc.path))
    if not deps:
        return []

    queries = [{"package": {"name": n, "ecosystem": e}, "version": v}
               for (e, n, v, *_rest) in deps]
    findings: list[Finding] = []
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(_OSV_BATCH, json={"queries": queries})
            if r.status_code != 200:
                log.warning("sca.osv_http", code=r.status_code)
                return []
            results = r.json().get("results", [])
            for (eco, name, ver, line, pos, path), res in zip(deps, results, strict=False):
                vulns = res.get("vulns") or []
                if not vulns:
                    continue
                ids = ", ".join(v.get("id", "?") for v in vulns[:5])
                fixed = await _fixed_version(c, vulns[0].get("id", ""), eco, name)
                findings.append(Finding(
                    file=path, line=line, diff_position=pos,
                    cwe="CWE-1395", rule_id=f"sca:{eco}:{name}",
                    severity=Severity.HIGH, confidence=0.97,
                    source=FindingSource.DETERMINISTIC,
                    title=f"Vulnerable dependency: {name} {ver} ({eco})",
                    rationale=f"{name}=={ver} is affected by known advisories: {ids}.",
                    exploit="Known CVE(s) in this exact version are reachable once "
                            "the dependency is installed.",
                    fix=(f"Upgrade {name} to {fixed} or later."
                         if fixed else f"Upgrade {name} to a non-affected version "
                                       "(see the linked advisories)."),
                ))
    except httpx.HTTPError as exc:
        log.warning("sca.network", error=str(exc))
        return []
    return findings


async def _fixed_version(
    client: httpx.AsyncClient, vuln_id: str, eco: str, name: str
) -> str | None:
    if not vuln_id:
        return None
    try:
        r = await client.get(f"{_OSV_VULN}{vuln_id}")
        if r.status_code != 200:
            return None
        for aff in r.json().get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("name") != name or pkg.get("ecosystem") != eco:
                continue
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        return str(ev["fixed"])
    except httpx.HTTPError:
        return None
=======
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
                    return f"Upgrade to >= {fixed}"
>>>>>>> Stashed changes
    return None
