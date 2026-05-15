"""Knowledge base CRUD — stores and retrieves security findings with pgvector."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from aegis.db.session import get_session_factory
from aegis.knowledge.embeddings import get_embedding, build_finding_text
from aegis.observability.logging import get_logger

log = get_logger(__name__)


async def upsert_findings_to_kb(findings: list[dict], pr_id=None) -> int:
    """Upsert security findings into the knowledge base with embeddings.

    Args:
        findings: List of normalized finding dicts.
        pr_id: Optional PR UUID for reference.

    Returns:
        Number of findings stored.
    """
    if not findings:
        return 0

    from aegis.db.models import KnowledgeBase

    # Generate embeddings for all findings
    texts = [build_finding_text(f) for f in findings]

    try:
        embeddings = await _batch_embed(texts)
    except Exception as exc:
        log.warning("kb.embedding_error", error=str(exc))
        embeddings = [[0.0] * 1536] * len(findings)

    session_factory = get_session_factory()
    stored = 0

    async with session_factory() as session:
        async with session.begin():
            for finding, embedding, text in zip(findings, embeddings, texts):
                # Skip if fingerprint already exists
                fingerprint = finding.get("fingerprint")
                if fingerprint:
                    existing = await _get_by_fingerprint(session, fingerprint)
                    if existing:
                        continue

                kb_entry = KnowledgeBase(
                    id=uuid.uuid4(),
                    vuln_type=finding.get("vuln_type", ""),
                    cwe=finding.get("cwe"),
                    severity=finding.get("severity", "info"),
                    description=finding.get("description", ""),
                    fix_snippet=finding.get("fix_snippet") or finding.get("fix"),
                    fingerprint=fingerprint,
                    embedding=embedding,
                    source_pr_id=pr_id,
                    created_at=datetime.now(timezone.utc),
                )
                session.add(kb_entry)
                stored += 1

    log.info("kb.upserted", count=stored, total=len(findings))
    return stored


async def get_kb_entry(entry_id: str) -> dict | None:
    """Get a single knowledge base entry by ID."""
    from aegis.db.models import KnowledgeBase
    from sqlalchemy import select

    session_factory = get_session_factory()
    async with session_factory() as session:
        result = await session.execute(
            select(KnowledgeBase).where(KnowledgeBase.id == uuid.UUID(entry_id))
        )
        entry = result.scalar_one_or_none()
        if entry:
            return _kb_to_dict(entry)
    return None


async def list_kb_entries(limit: int = 100, offset: int = 0) -> list[dict]:
    """List knowledge base entries with pagination."""
    from aegis.db.models import KnowledgeBase
    from sqlalchemy import select

    session_factory = get_session_factory()
    async with session_factory() as session:
        result = await session.execute(
            select(KnowledgeBase)
            .order_by(KnowledgeBase.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        entries = result.scalars().all()
        return [_kb_to_dict(e) for e in entries]


async def _batch_embed(texts: list[str]) -> list[list[float]]:
    """Embed texts in small batches to avoid API rate limits."""
    from aegis.knowledge.embeddings import get_embeddings
    return await get_embeddings(texts)


async def _get_by_fingerprint(session, fingerprint: str):
    from aegis.db.models import KnowledgeBase
    from sqlalchemy import select

    result = await session.execute(
        select(KnowledgeBase).where(KnowledgeBase.fingerprint == fingerprint)
    )
    return result.scalar_one_or_none()


def _kb_to_dict(entry) -> dict:
    return {
        "id": str(entry.id),
        "vuln_type": entry.vuln_type,
        "cwe": entry.cwe,
        "severity": entry.severity,
        "description": entry.description,
        "fix_snippet": entry.fix_snippet,
        "fingerprint": entry.fingerprint,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }
