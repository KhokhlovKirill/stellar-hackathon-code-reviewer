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
    return None
