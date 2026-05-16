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
from aegis.pipeline.i18n import localize_findings_inplace, t
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
    lang = getattr(state.ctx, "lang", "en") or "en"

    # Deterministic findings carry English template text — translate them to
    # the repo's configured comment language before they are posted. LLM
    # findings are already produced in that language by the analysis stage.
    localize_findings_inplace(state.findings, lang)

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
        body = render_inline_comment(finding, lang)
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

    await _index_published_findings(state, gate)

    log.info(
        "render.posted",
        scan_id=state.scan_id,
        inline_comments=posted,
        deduped=skipped,
        summary_ref=state.summary_ref,
    )


async def _index_published_findings(state: PipelineState, gate: int) -> None:
    """Index published (confirmed) findings into the Security KB.

    These survived deterministic + LLM judge + suppression, so they are the
    repo's confirmed-finding memory for future "similar to PR #N" recall.
    Best-effort: never raises, never blocks the scan.
    """
    try:
        from aegis.kb.store import index_finding
    except Exception:
        return
    for finding in state.findings:
        if finding.severity.rank < gate:
            continue
        try:
            await index_finding(
                repo_slug=state.pr.repo_slug,
                provider=state.ev.provider.value,
                pr_id=state.pr.pr_id,
                scan_id=state.scan_id,
                finding=finding,
                snippet=state.context_map.get(finding.file, ""),
            )
        except Exception as exc:
            log.warning("render.kb_index_failed", scan_id=state.scan_id, error=str(exc))


def render_inline_comment(finding: Finding, lang: str = "en") -> str:
    parts = [
        f"**{t('finding_header', lang)}: {finding.severity.value.upper()}**",
        "",
        f"**{finding.title}**",
        f"- {t('cwe', lang)}: `{finding.cwe or 'n/a'}`",
        f"- {t('confidence', lang)}: `{finding.confidence:.2f}`",
        "",
        finding.rationale,
    ]
    if finding.exploit:
        parts.extend(["", f"**{t('exploit_scenario', lang)}**", finding.exploit])
    if finding.fix:
        parts.extend(["", f"**{t('suggested_fix', lang)}**"])
        fence = "suggestion" if finding.fix_is_suggestion else ""
        parts.append(f"```{fence}\n{finding.fix}\n```")
    parts.append(f"\n{t('fingerprint', lang)}: `{finding.fingerprint()}`")
    return "\n".join(parts)


def render_summary(state: PipelineState) -> str:
    lang = getattr(state.ctx, "lang", "en") or "en"
    counts = _severity_counts(state.findings)
    breakdown = risk_breakdown(state.findings)
    lines = [
        f"## {t('review_title', lang)}",
        "",
        f"{t('risk_score', lang)}: **{state.risk_score}/100** (`{state.risk_label}`)",
        f"{t('scan_id', lang)}: `{state.scan_id}`",
        f"{t('head_sha', lang)}: `{state.pr.head_sha}`",
        "",
        f"| {t('severity', lang)} | {t('count', lang)} |",
        "|---|---:|",
    ]
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        lines.append(f"| {sev.value} | {counts.get(sev.value, 0)} |")

    lines.extend(["", f"**{t('scanned_files', lang)}**"])
    lines.extend(f"- `{path}`" for path in state.result.files_scanned)
    if not state.result.files_scanned:
        lines.append(f"- {t('none', lang)}")

    if state.result.files_skipped:
        lines.extend(["", f"**{t('skipped_files', lang)}**"])
        for skipped in state.result.files_skipped[:30]:
            lines.append(f"- `{skipped['path']}`: {skipped['reason']}")

    if breakdown:
        lines.extend(["", f"**{t('risk_breakdown', lang)}**"])
        lines.extend(f"- `{k}`: +{v}" for k, v in sorted(breakdown.items()))

    if state.blast_radius_mermaid:
        lines.extend(
            ["", f"**{t('blast_radius', lang)}**", "```mermaid", state.blast_radius_mermaid, "```"]
        )

    if state.kb_matches:
        lines.extend(["", f"**{t('recurring_patterns', lang)}**"])
        for fp, hits in list(state.kb_matches.items())[:10]:
            top = hits[0]
            lines.append(
                f"- `{fp[:8]}` {t('similar_to', lang)} {top['cwe']} "
                f"{t('in_pr', lang)} #{top['pr_id']} (sim {top['similarity']})"
            )

    if state.result.degraded:
        lines.extend(["", f"**{t('degraded_components', lang)}**"])
        lines.extend(f"- `{item}`" for item in state.result.degraded)

    if state.suppressed_findings:
        lines.extend(["", f"**{t('suppressed_by_feedback', lang)}**"])
        lines.extend(
            f"- `{finding.file}:{finding.line}` {finding.title}"
            for finding in state.suppressed_findings[:20]
        )

    if not state.findings:
        lines.extend(["", t("no_findings", lang)])
    else:
        lines.extend(["", t("reply_hint", lang)])

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
