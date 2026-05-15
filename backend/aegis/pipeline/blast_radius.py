"""Generate Mermaid blast-radius diagrams for SCA findings."""

from __future__ import annotations

import re

from aegis.obs import get_logger
from aegis.pipeline.state import PipelineState

log = get_logger("aegis.blast_radius")


async def generate_blast_radius(state: PipelineState) -> None:
    mermaid = build_blast_radius(state.context_map, _sca_packages(state))
    state.blast_radius_mermaid = mermaid
    if mermaid:
        log.info("blast_radius.generated", scan_id=state.scan_id)


def build_blast_radius(context_map: dict[str, str], packages: set[str]) -> str | None:
    if not packages:
        return None
    edges: set[tuple[str, str]] = set()
    for path, context in context_map.items():
        imports = _imports(context)
        for package in packages:
            root = package.split("/", 1)[0].split(".", 1)[0]
            if package in imports or root in imports:
                edges.add((path, package))
    if not edges:
        return None
    lines = ["graph TD"]
    for path, package in sorted(edges):
        lines.append(f"  {node(path)}[{path}] --> {node(package)}[{package}]")
    return "\n".join(lines)


def _sca_packages(state: PipelineState) -> set[str]:
    packages: set[str] = set()
    for finding in state.findings:
        if not finding.rule_id or not finding.rule_id.startswith("sca:"):
            continue
        parts = finding.rule_id.split(":", 2)
        if len(parts) == 3:
            packages.add(parts[2])
    return packages


def _imports(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        body = line.split(":", 1)[-1].strip()
        m = re.match(r"import\s+([A-Za-z0-9_.,\s]+)", body)
        if m:
            out.update(part.strip().split(" as ")[0] for part in m.group(1).split(","))
        m = re.match(r"from\s+([A-Za-z0-9_.]+)\s+import\s+", body)
        if m:
            out.add(m.group(1).split(".", 1)[0])
    return {item for item in out if item}


def node(value: str) -> str:
    return "n" + re.sub(r"[^A-Za-z0-9_]", "_", value)
