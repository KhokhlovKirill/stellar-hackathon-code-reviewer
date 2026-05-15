"""Knowledge base CRUD — stores and retrieves security findings with pgvector."""

from __future__ import annotations

from datetime import datetime, timezone

from aegis.db.session import get_session_factory
from aegis.knowledge.embeddings import build_finding_text
from aegis.observability.logging import get_logger

log = get_logger(__name__)

_EMBEDDING_DIM = 1536


async def upsert_findings_to_kb(findings: list[dict], pr_id: int | str | None = None) -> int:
    """Upsert security findings into the knowledge base with embeddings.

    De-duplicates against existing rows by ``vuln_type`` + ``description`` —
    matching rows have their ``frequency`` counter bumped instead of being
    inserted again.

    Args:
        findings: List of normalized finding dicts.
        pr_id: Optional ``pull_requests.id`` (used to look up the related PR
            number for cross-referencing).

    Returns:
        Number of *new* findings stored (excluding dedupe hits).
    """
    if not findings:
        return 0

    from aegis.db.models import KnowledgeBase, PullRequest
    from sqlalchemy import select

    # Generate embeddings for all findings
    texts = [build_finding_text(f) for f in findings]

    try:
        embeddings = await _batch_embed(texts)
    except Exception as exc:
        log.warning("kb.embedding_error", error=str(exc))
        embeddings = [[0.0] * _EMBEDDING_DIM] * len(findings)

    # Resolve repo_id + pr_number from the PR row, if any
    repo_id: int | None = None
    pr_number: int | None = None
    pr_pk: int | None = None
    try:
        if pr_id is not None and str(pr_id).isdigit():
            pr_pk = int(pr_id)
    except (TypeError, ValueError):
        pr_pk = None

    session_factory = get_session_factory()
    stored = 0

    async with session_factory() as session:
        if pr_pk is not None:
            pr_row = (await session.execute(
                select(PullRequest).where(PullRequest.id == pr_pk)
            )).scalar_one_or_none()
            if pr_row is not None:
                repo_id = pr_row.repo_id
                pr_number = pr_row.pr_number

        async with session.begin():
            for finding, embedding, _text in zip(findings, embeddings, texts):
                vuln_type = (finding.get("vuln_type") or "").strip()
                description = (finding.get("description") or "").strip()
                if not description:
                    # KnowledgeBase.description is NOT NULL.
                    continue

                # Dedup by (repo_id, vuln_type, description) — bump frequency on hit
                existing = (await session.execute(
                    select(KnowledgeBase).where(
                        KnowledgeBase.repo_id == repo_id,
                        KnowledgeBase.vuln_type == vuln_type,
                        KnowledgeBase.description == description,
                    ).limit(1)
                )).scalar_one_or_none()

                if existing is not None:
                    existing.frequency = (existing.frequency or 0) + 1
                    existing.updated_at = datetime.now(timezone.utc)
                    continue

                kb_entry = KnowledgeBase(
                    repo_id=repo_id,
                    pr_number=pr_number,
                    vuln_type=vuln_type or None,
                    cwe=finding.get("cwe"),
                    severity=finding.get("severity", "info"),
                    description=description,
                    fix_snippet=finding.get("fix_snippet") or finding.get("fix"),
                    file_path=finding.get("file_path"),
                    code_snippet=finding.get("match_snippet"),
                    embedding=embedding,
                    created_at=datetime.now(timezone.utc),
                )
                session.add(kb_entry)
                stored += 1

    log.info("kb.upserted", new=stored, total=len(findings))
    return stored


async def get_kb_entry(entry_id: str | int) -> dict | None:
    """Get a single knowledge base entry by ID."""
    from aegis.db.models import KnowledgeBase
    from sqlalchemy import select

    try:
        entry_pk = int(entry_id)
    except (TypeError, ValueError):
        return None

    session_factory = get_session_factory()
    async with session_factory() as session:
        result = await session.execute(
            select(KnowledgeBase).where(KnowledgeBase.id == entry_pk)
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


def _kb_to_dict(entry) -> dict:
    return {
        "id": str(entry.id),
        "repo_id": str(entry.repo_id) if entry.repo_id is not None else None,
        "pr_number": entry.pr_number,
        "vuln_type": entry.vuln_type,
        "cwe": entry.cwe,
        "severity": entry.severity,
        "description": entry.description,
        "fix_snippet": entry.fix_snippet,
        "file_path": entry.file_path,
        "frequency": entry.frequency,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }
