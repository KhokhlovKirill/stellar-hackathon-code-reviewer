"""Stage wrapper: run the deterministic detectors and record their findings.

Order: secrets (pure) → Semgrep (needs full content of changed files) → SCA
(changed manifests). Runs regardless of LLM availability — this is the safety net
for C3. Findings are appended to state and persisted.
"""

from __future__ import annotations

import asyncio

from sqlalchemy import select

from aegis.db import get_session
from aegis.db.models import FindingRow, Scan
from aegis.obs import get_logger, metrics
from aegis.pipeline.deterministic.bandit import run_bandit
from aegis.pipeline.deterministic.gitleaks import run_gitleaks
from aegis.pipeline.deterministic.sca import run_sca
from aegis.pipeline.deterministic.secrets import scan_secrets
from aegis.pipeline.deterministic.semgrep import run_semgrep
from aegis.pipeline.state import PipelineState
from aegis.providers import get_provider
from aegis.schemas import Finding

log = get_logger("aegis.deterministic")


async def _persist(scan_id: str, findings: list[Finding]) -> None:
    if not findings:
        return
    async with get_session() as s:
        scan = (await s.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
        if scan is None:
            return
        for f in findings:
            s.add(FindingRow(
                scan_id=scan_id, fingerprint=f.fingerprint(), file=f.file, line=f.line,
                cwe=f.cwe, rule_id=f.rule_id, severity=f.severity.value,
                confidence=f.confidence, source=f.source.value, title=f.title,
                rationale=f.rationale, exploit=f.exploit, fix=f.fix,
            ))


async def run_deterministic(state: PipelineState) -> None:
    code = state.code_files
    findings: list[Finding] = []

    # 1. Secrets — pure, no network.
    sec = scan_secrets(code)
    findings.extend(sec)

    # 2. Gitleaks — external high-precision scanner over added lines only.
    try:
        gl = await run_gitleaks(code)
        findings.extend(gl)
    except FileNotFoundError:
        state.result.degraded.append("gitleaks")
        log.warning("deterministic.gitleaks_missing")
        gl = []

    # 3. Semgrep/Bandit — need full content of the changed files (never whole repo).
    file_texts: dict[str, str] = {}
    provider = get_provider(state.ev.provider)
    if code and state.ctx.access_token:
        async def _fetch(path: str) -> tuple[str, str | None]:
            try:
                return path, await provider.fetch_file(
                    state.pr, state.ctx.access_token, path
                )
            except Exception as exc:
                log.warning("deterministic.fetch_file_failed", path=path, error=str(exc))
                return path, None

        for path, text in await asyncio.gather(*[_fetch(f.path) for f in code]):
            if text is not None:
                file_texts[path] = text

    changed_map = {f.path: f for f in code}
    try:
        sg = await run_semgrep(file_texts, changed_map)
        findings.extend(sg)
    except FileNotFoundError:
        state.result.degraded.append("semgrep")
        log.warning("deterministic.semgrep_missing")
        sg = []

    try:
        bd = await run_bandit(file_texts, changed_map)
        findings.extend(bd)
    except FileNotFoundError:
        state.result.degraded.append("bandit")
        log.warning("deterministic.bandit_missing")
        bd = []

    # 4. SCA — changed dependency manifests.
    sca = await run_sca(state.manifest_files)
    findings.extend(sca)

    state.findings.extend(findings)
    for f in findings:
        metrics.findings_total.labels(
            f.severity.value, f.cwe or "n/a", f.source.value
        ).inc()
    await _persist(state.scan_id, findings)

    log.info(
        "deterministic.done", scan_id=state.scan_id,
        secrets=len(sec), gitleaks=len(gl), semgrep=len(sg), bandit=len(bd),
        sca=len(sca), total=len(findings),
    )
