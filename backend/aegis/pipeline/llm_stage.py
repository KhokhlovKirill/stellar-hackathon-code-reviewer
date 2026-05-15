"""LLM ensemble stage: local security model + generalist + judge."""

from __future__ import annotations

import asyncio

from sqlalchemy import select

from aegis.db import get_session
from aegis.db.models import FindingRow, LLMCall, Scan
from aegis.llm.base import LLMCompletion, LLMError
from aegis.llm.parser import finding_schema, parse_findings
from aegis.llm.prompt import judge_messages, review_messages
from aegis.llm.router import LLMRouter
from aegis.obs import get_logger, metrics
from aegis.pipeline.state import PipelineState
from aegis.schemas import Finding, FindingSource

log = get_logger("aegis.llm_stage")


def _changed_lines(state: PipelineState) -> dict[str, set[int]]:
    return {
        fc.path: {ln.new_lineno for ln in fc.added_lines() if ln.new_lineno is not None}
        for fc in state.code_files
    }


def _diff_positions(state: PipelineState) -> dict[tuple[str, int], int | None]:
    out: dict[tuple[str, int], int | None] = {}
    for fc in state.code_files:
        for ln in fc.added_lines():
            if ln.new_lineno is not None:
                out[(fc.path, ln.new_lineno)] = ln.diff_position
    return out


async def _persist_calls(scan_id: str, calls: list[LLMCompletion], ok: bool = True) -> None:
    async with get_session() as s:
        for c in calls:
            s.add(LLMCall(
                scan_id=scan_id,
                tier=c.tier,
                model=c.model,
                role=c.role,
                prompt_tokens=c.usage.prompt_tokens,
                completion_tokens=c.usage.completion_tokens,
                latency_ms=c.latency_ms,
                cost_usd=c.usage.cost_usd,
                ok=ok,
            ))


async def _persist_findings(scan_id: str, findings: list[Finding]) -> None:
    if not findings:
        return
    async with get_session() as s:
        scan = (await s.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
        if scan is None:
            return
        for f in findings:
            s.add(FindingRow(
                scan_id=scan_id,
                fingerprint=f.fingerprint(),
                file=f.file,
                line=f.line,
                cwe=f.cwe,
                rule_id=f.rule_id,
                severity=f.severity.value,
                confidence=f.confidence,
                source=f.source.value,
                title=f.title,
                rationale=f.rationale,
                exploit=f.exploit,
                fix=f.fix,
            ))


async def run_llm_analysis(state: PipelineState) -> None:
    if not state.code_files:
        log.info("llm.skip_no_code", scan_id=state.scan_id)
        state.result.findings = list(state.findings)
        return

    router = LLMRouter()
    schema = finding_schema()
    changed = _changed_lines(state)
    positions = _diff_positions(state)
    det = [f for f in state.findings if f.source is FindingSource.DETERMINISTIC]

    messages = review_messages(
        repo=state.pr.repo_slug,
        pr_id=state.pr.pr_id,
        files=state.code_files,
        deterministic_findings=det,
        context_map=state.context_map,
    )

    async def _run(role: str) -> LLMCompletion | None:
        try:
            return await router.complete(role=role, messages=messages, schema=schema)
        except LLMError as exc:
            state.result.degraded.append(role)
            log.warning(
                "llm.detector_unavailable",
                scan_id=state.scan_id,
                role=role,
                error=str(exc),
            )
            return None

    detector_a, detector_b = await asyncio.gather(_run("detector_a"), _run("detector_b"))
    calls = [c for c in (detector_a, detector_b) if c is not None]
    await _persist_calls(state.scan_id, calls)

    candidates: list[Finding] = []
    if detector_a is not None:
        candidates.extend(parse_findings(
            detector_a.content,
            source=FindingSource.LLM_A,
            changed_lines=changed,
            diff_positions=positions,
        ))
    if detector_b is not None:
        candidates.extend(parse_findings(
            detector_b.content,
            source=FindingSource.LLM_B,
            changed_lines=changed,
            diff_positions=positions,
        ))

    final_llm: list[Finding] = []
    if candidates:
        try:
            judge = await router.complete(
                role="judge",
                messages=judge_messages(
                    repo=state.pr.repo_slug,
                    pr_id=state.pr.pr_id,
                    files=state.code_files,
                    candidates=[*det, *candidates],
                    context_map=state.context_map,
                ),
                schema=schema,
            )
            await _persist_calls(state.scan_id, [judge])
            final_llm = parse_findings(
                judge.content,
                source=FindingSource.JUDGE,
                changed_lines=changed,
                diff_positions=positions,
            )
        except LLMError as exc:
            state.result.degraded.append("judge")
            log.warning("llm.judge_unavailable", scan_id=state.scan_id, error=str(exc))
            final_llm = _fallback_consolidate(candidates)

    state.findings.extend(final_llm)
    state.result.findings = list(state.findings)
    for f in final_llm:
        metrics.findings_total.labels(f.severity.value, f.cwe or "n/a", f.source.value).inc()
    await _persist_findings(state.scan_id, final_llm)
    log.info(
        "llm.done",
        scan_id=state.scan_id,
        candidates=len(candidates),
        published=len(final_llm),
        degraded=state.result.degraded,
    )


def _fallback_consolidate(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for f in sorted(findings, key=lambda x: (x.file, x.line, x.cwe or "", -x.confidence)):
        key = f"{f.file}:{f.line}:{f.cwe or f.title}"
        if key in seen or f.confidence < 0.80:
            continue
        seen.add(key)
        out.append(f)
    return out
