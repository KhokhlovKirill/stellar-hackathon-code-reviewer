"""Security KB store: index confirmed findings, query similar prior findings.

Similarity is repo-scoped cosine over the most-recent `candidate_limit` entries
(recency bound keeps the in-process scan O(N) and fast). For installs that
outgrow that, the JSON embedding column migrates to a native pgvector index
behind this same API.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError

from aegis.config import get_config
from aegis.db import get_session
from aegis.db.models import KnowledgeEntry
from aegis.kb.embeddings import cosine, embed
from aegis.obs import get_logger, metrics
from aegis.schemas import Finding

log = get_logger("aegis.kb.store")


@dataclass(frozen=True, slots=True)
class SimilarHit:
    pr_id: str
    scan_id: str
    cwe: str | None
    title: str
    file: str
    similarity: float


async def index_finding(
    *,
    repo_slug: str,
    provider: str,
    pr_id: str,
    scan_id: str,
    finding: Finding,
    snippet: str = "",
) -> bool:
    """Embed a confirmed finding and upsert it into the KB. Returns True if stored."""
    cfg = get_config().kb
    if not cfg.enabled:
        return False
    vec = await embed(finding.title, snippet or finding.rationale, finding.cwe)
    if vec is None:
        return False

    fp = finding.fingerprint()
    values = {
        "repo_slug": repo_slug,
        "provider": provider,
        "pr_id": pr_id,
        "scan_id": scan_id,
        "fingerprint": fp,
        "cwe": finding.cwe,
        "severity": finding.severity.value,
        "file": finding.file,
        "title": finding.title[:500],
        "snippet": (snippet or finding.rationale)[:2000],
        "embedding": vec,
        "confirmed": True,
    }
    try:
        async with get_session() as s:
            dialect = s.bind.dialect.name if s.bind else ""
            if dialect == "postgresql":
                stmt = (
                    pg_insert(KnowledgeEntry)
                    .values(**values)
                    .on_conflict_do_nothing(constraint="uq_kb_repo_fingerprint")
                )
                await s.execute(stmt)
            else:
                exists = (
                    await s.execute(
                        select(KnowledgeEntry.id).where(
                            KnowledgeEntry.repo_slug == repo_slug,
                            KnowledgeEntry.fingerprint == fp,
                        )
                    )
                ).scalar_one_or_none()
                if exists is None:
                    s.add(KnowledgeEntry(**values))
        metrics.kb_indexed_total.inc()
        return True
    except IntegrityError:
        return False
    except Exception as exc:
        log.warning("kb.index_failed", error=str(exc), fingerprint=fp)
        return False


async def query_similar(
    *,
    repo_slug: str,
    finding: Finding,
    snippet: str = "",
    exclude_fingerprint: str | None = None,
) -> list[SimilarHit]:
    """Return prior confirmed findings in this repo similar to `finding`."""
    cfg = get_config().kb
    if not cfg.enabled:
        return []
    vec = await embed(finding.title, snippet or finding.rationale, finding.cwe)
    if vec is None:
        return []

    try:
        async with get_session() as s:
            rows = (
                await s.execute(
                    select(KnowledgeEntry)
                    .where(
                        KnowledgeEntry.repo_slug == repo_slug,
                        KnowledgeEntry.confirmed.is_(True),
                    )
                    .order_by(KnowledgeEntry.created_at.desc())
                    .limit(cfg.candidate_limit)
                )
            ).scalars().all()
    except Exception as exc:
        log.warning("kb.query_failed", error=str(exc))
        return []

    scored: list[SimilarHit] = []
    for row in rows:
        if exclude_fingerprint and row.fingerprint == exclude_fingerprint:
            continue
        sim = cosine(vec, list(row.embedding or []))
        if sim >= cfg.min_similarity:
            scored.append(SimilarHit(
                pr_id=row.pr_id,
                scan_id=row.scan_id,
                cwe=row.cwe,
                title=row.title,
                file=row.file,
                similarity=round(sim, 4),
            ))

    scored.sort(key=lambda h: h.similarity, reverse=True)
    top = scored[: cfg.top_k]
    if top:
        metrics.kb_hits_total.inc()
    return top
