"""KB enrichment stage: annotate findings with similar prior confirmed findings.

For each surviving finding we query the Security KB (repo-scoped embedding
similarity). Matches are recorded on the finding's rationale and in state so the
inline comment and summary can show "similar to a confirmed finding in PR #142".

This runs after risk_score/blast_radius (findings are final) and before render.
Fully graceful: if embeddings/KB are unavailable the stage is a no-op.
"""

from __future__ import annotations

from aegis.config import get_config
from aegis.kb.store import query_similar
from aegis.obs import get_logger
from aegis.pipeline.state import PipelineState

log = get_logger("aegis.kb_enrich")


def _snippet_for(state: PipelineState, file: str, line: int) -> str:
    """Best-effort surrounding code for embedding (narrow context if available)."""
    ctx = state.context_map.get(file)
    if ctx:
        return ctx[:2000]
    for fc in state.code_files:
        if fc.path != file:
            continue
        for h in fc.hunks:
            for ln in h.lines:
                if ln.new_lineno == line:
                    return ln.content
    return ""


async def enrich_with_kb(state: PipelineState) -> None:
    cfg = get_config().kb
    if not cfg.enabled or not state.findings:
        return

    enriched = 0
    for finding in state.findings:
        fp = finding.fingerprint()
        snippet = _snippet_for(state, finding.file, finding.line)
        hits = await query_similar(
            repo_slug=state.pr.repo_slug,
            finding=finding,
            snippet=snippet,
            exclude_fingerprint=fp,
        )
        if not hits:
            continue

        state.kb_matches[fp] = [
            {
                "pr_id": h.pr_id,
                "cwe": h.cwe or "n/a",
                "similarity": f"{h.similarity:.2f}",
                "title": h.title,
            }
            for h in hits
        ]
        top = hits[0]
        note = (
            f"\n\n🔁 **Recurring pattern** — similar to a confirmed "
            f"{top.cwe or 'finding'} in PR #{top.pr_id} "
            f"(similarity {top.similarity:.2f})."
        )
        if len(hits) > 1:
            note += f" {len(hits)} related prior findings in this repo."
        finding.rationale = (finding.rationale + note)[:1800]
        enriched += 1

    log.info(
        "kb_enrich.done",
        scan_id=state.scan_id,
        findings=len(state.findings),
        enriched=enriched,
    )
