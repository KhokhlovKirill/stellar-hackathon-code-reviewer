"""False-positive learning and suppression stage."""

from __future__ import annotations

from sqlalchemy import func, select

from aegis.db import get_session
from aegis.db.models import Feedback
from aegis.obs import get_logger
from aegis.pipeline.state import PipelineState
from aegis.schemas import Finding

log = get_logger("aegis.suppression")

FP_SUPPRESS_THRESHOLD = 3


async def apply_suppression(state: PipelineState) -> None:
    fingerprints = [f.fingerprint() for f in state.findings]
    if not fingerprints:
        return
    suppressed = await _suppressed_fingerprints(fingerprints)
    if not suppressed:
        return

    kept, dropped = suppress_findings(state.findings, suppressed)
    state.findings = kept
    state.suppressed_findings.extend(dropped)
    state.result.findings = list(kept)
    log.info(
        "suppression.applied",
        scan_id=state.scan_id,
        suppressed=len(dropped),
        fingerprints=sorted(suppressed)[:20],
    )


def suppress_findings(
    findings: list[Finding], suppressed_fingerprints: set[str]
) -> tuple[list[Finding], list[Finding]]:
    kept: list[Finding] = []
    dropped: list[Finding] = []
    for finding in findings:
        if finding.fingerprint() in suppressed_fingerprints:
            dropped.append(finding)
        else:
            kept.append(finding)
    return kept, dropped


async def _suppressed_fingerprints(fingerprints: list[str]) -> set[str]:
    async with get_session() as session:
        rows = await session.execute(
            select(Feedback.finding_fingerprint, func.count(Feedback.id))
            .where(
                Feedback.kind == "false_positive",
                Feedback.finding_fingerprint.in_(fingerprints),
            )
            .group_by(Feedback.finding_fingerprint)
        )
        return {
            str(fp) for fp, count in rows.all()
            if int(count) >= FP_SUPPRESS_THRESHOLD
        }
