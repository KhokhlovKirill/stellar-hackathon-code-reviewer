"""Render findings and publish review comments to the VCS provider.

Comment dedup: on every synchronize push to the same PR, we query previously
posted comment_refs by fingerprint so we don't create duplicates. A finding that
already has a comment just updates the FindingRow reference; it doesn't post again.
"""

from __future__ import annotations

from sqlalchemy import select, update

from aegis.db import get_session
from aegis.db.models import FindingRow
from aegis.obs import get_logger
from aegis.pipeline.risk_score import risk_breakdown
from aegis.pipeline.state import PipelineState
from aegis.providers import get_provider
from aegis.schemas import Finding, ReviewComment, Severity

log = get_logger("aegis.render")


async def _existing_comment_refs(
    repo_slug: str, pr_id: str, fingerprints: list[str]
) -> dict[str, str]:
    """Return {fingerprint: comment_ref} for findings already posted on this PR."""
    if not fingerprints:
        return {}
    async with get_session() as s:
        rows = (
            await s.execute(
                select(FindingRow.fingerprint, FindingRow.comment_ref)
                .where(
                    FindingRow.comment_ref.is_not(None),
                    FindingRow.fingerprint.in_(fingerprints),
                )
            )
        ).all()
    return {r.fingerprint: r.comment_ref for r in rows if r.comment_ref}


async def _save_comment_ref(scan_id: str, fingerprint: str, ref: str) -> None:
    async with get_session() as s:
        await s.execute(
            update(FindingRow)
            .where(FindingRow.scan_id == scan_id, FindingRow.fingerprint == fingerprint)
            .values(comment_ref=ref)
        )


async def render_and_post(state: PipelineState) -> None:
    if not state.ctx.access_token:
        state.result.degraded.append("render:no_token")
        return

    provider = get_provider(state.ev.provider)
    gate = _severity_rank(state.ctx.severity_gate)

    fingerprints = [f.fingerprint() for f in state.findings]
    existing = await _existing_comment_refs(state.pr.repo_slug, state.pr.pr_id, fingerprints)

    posted = skipped = 0
    for finding in state.findings:
        if finding.severity.rank < gate:
            continue
        fp = finding.fingerprint()
        if fp in existing:
            # Already commented on a previous scan for this PR — don't duplicate.
            state.posted_refs.append(existing[fp])
            skipped += 1
            continue
        body = render_inline_comment(finding)
        try:
            ref = await provider.post_inline_comment(
                state.pr,
                state.ctx.access_token,
                ReviewComment(
                    file=finding.file,
                    line=finding.line,
                    diff_position=finding.diff_position,
                    body=body,
                    finding_fingerprint=fp,
                ),
            )
            state.posted_refs.append(ref)
            await _save_comment_ref(state.scan_id, fp, ref)
            posted += 1
        except Exception as exc:
            log.warning("render.inline_failed", scan_id=state.scan_id,
                        file=finding.file, line=finding.line, error=str(exc))

    summary = render_summary(state)
    try:
        state.summary_ref = await provider.post_summary(
            state.pr, state.ctx.access_token, summary
        )
    except Exception as exc:
        log.warning("render.summary_failed", scan_id=state.scan_id, error=str(exc))

    log.info(
        "render.posted",
        scan_id=state.scan_id,
        inline_comments=posted,
        deduped=skipped,
        summary_ref=state.summary_ref,
    )


def render_inline_comment(finding: Finding) -> str:
    parts = [
        f"**Aegis security finding: {finding.severity.value.upper()}**",
        "",
        f"**{finding.title}**",
        f"- CWE: `{finding.cwe or 'n/a'}`",
        f"- Confidence: `{finding.confidence:.2f}`",
        "",
        finding.rationale,
    ]
    if finding.exploit:
        parts.extend(["", "**Exploit scenario**", finding.exploit])
    if finding.fix:
        parts.extend(["", "**Suggested fix**"])
        fence = "suggestion" if finding.fix_is_suggestion else ""
        parts.append(f"```{fence}\n{finding.fix}\n```")
    parts.append(f"\nFinding fingerprint: `{finding.fingerprint()}`")
    return "\n".join(parts)


def render_summary(state: PipelineState) -> str:
    counts = _severity_counts(state.findings)
    breakdown = risk_breakdown(state.findings)
    lines = [
        "## Aegis security review",
        "",
        f"Risk Score: **{state.risk_score}/100** (`{state.risk_label}`)",
        f"Scan ID: `{state.scan_id}`",
        f"Head SHA: `{state.pr.head_sha}`",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        lines.append(f"| {sev.value} | {counts.get(sev.value, 0)} |")

    lines.extend(["", "**Scanned files**"])
    lines.extend(f"- `{path}`" for path in state.result.files_scanned)
    if not state.result.files_scanned:
        lines.append("- none")

    if state.result.files_skipped:
        lines.extend(["", "**Skipped files**"])
        for skipped in state.result.files_skipped[:30]:
            lines.append(f"- `{skipped['path']}`: {skipped['reason']}")

    if breakdown:
        lines.extend(["", "**Risk breakdown**"])
        lines.extend(f"- `{k}`: +{v}" for k, v in sorted(breakdown.items()))

    if state.blast_radius_mermaid:
        lines.extend(["", "**Blast Radius**", "```mermaid", state.blast_radius_mermaid, "```"])

    if state.result.degraded:
        lines.extend(["", "**Degraded components**"])
        lines.extend(f"- `{item}`" for item in state.result.degraded)

    if state.suppressed_findings:
        lines.extend(["", "**Suppressed by team feedback**"])
        lines.extend(
            f"- `{finding.file}:{finding.line}` {finding.title}"
            for finding in state.suppressed_findings[:20]
        )

    if not state.findings:
        lines.extend(["", "No confirmed security findings on changed code lines."])
    else:
        lines.extend(["", "Reply to an Aegis thread with `@secbot why` for details."])

    return "\n".join(lines)


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    out = {severity.value: 0 for severity in Severity}
    for f in findings:
        out[f.severity.value] += 1
    return out


def _severity_rank(value: str) -> int:
    try:
        return Severity(value).rank
    except ValueError:
        return Severity.MEDIUM.rank
