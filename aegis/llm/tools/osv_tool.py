"""LangChain tool for querying the OSV vulnerability database."""

from __future__ import annotations

import json

from langchain_core.tools import tool


@tool
async def query_osv(package_name: str, package_version: str, ecosystem: str = "PyPI") -> str:
    """Query the OSV database for known vulnerabilities in a package.

    Args:
        package_name: Name of the package (e.g. 'requests').
        package_version: Version string (e.g. '2.25.0').
        ecosystem: Package ecosystem ('PyPI', 'npm', 'Go', 'Maven', etc.).

    Returns:
        JSON string with vulnerability information.
    """
    import httpx

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                "https://api.osv.dev/v1/query",
                json={
                    "package": {"name": package_name, "ecosystem": ecosystem},
                    "version": package_version,
                },
            )
            r.raise_for_status()
            data = r.json()
            vulns = data.get("vulns", [])
            if not vulns:
                return json.dumps({"status": "no_vulnerabilities", "package": package_name, "version": package_version})

            summary = []
            for v in vulns[:5]:
                summary.append({
                    "id": v.get("id"),
                    "summary": v.get("summary", ""),
                    "severity": [s.get("score") for s in v.get("severity", [])],
                    "aliases": v.get("aliases", []),
                })
            return json.dumps({"package": package_name, "version": package_version, "vulnerabilities": summary})
    except Exception as exc:
        return json.dumps({"error": str(exc)})
