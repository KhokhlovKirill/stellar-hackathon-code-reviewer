"""ORM models — full audit trail (docs/08, docs/09).

repo_secrets stores ciphertext only; plaintext tokens never touch the DB.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Repository(Base):
    __tablename__ = "repositories"
    __table_args__ = (UniqueConstraint("provider", "external_id", name="uq_repo_provider_extid"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    external_id: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    secrets: Mapped[list[RepoSecret]] = relationship(back_populates="repo")
    policy: Mapped[RepoPolicy | None] = relationship(back_populates="repo", uselist=False)


class RepoSecret(Base):
    __tablename__ = "repo_secrets"

    id: Mapped[int] = mapped_column(primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(32))           # access_token | webhook_secret
    ciphertext: Mapped[str] = mapped_column(Text)            # vault-encrypted, never plaintext
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    repo: Mapped[Repository] = relationship(back_populates="secrets")


class RepoPolicy(Base):
    __tablename__ = "repo_policies"

    repo_id: Mapped[int] = mapped_column(
        ForeignKey("repositories.id", ondelete="CASCADE"), primary_key=True
    )
    severity_gate: Mapped[str] = mapped_column(String(16), default="medium")
    merge_block: Mapped[str] = mapped_column(String(16), default="critical")
    ignore_globs: Mapped[list[str]] = mapped_column(JSON, default=list)
    ensemble_profile: Mapped[str] = mapped_column(String(32), default="det+don+judge")
    prompt_overrides: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    lang: Mapped[str] = mapped_column(String(4), default="ru")
    budgets: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    repo: Mapped[Repository] = relationship(back_populates="policy")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)   # scan_id (uuid)
    provider: Mapped[str] = mapped_column(String(16))
    repo_slug: Mapped[str] = mapped_column(String(255))
    pr_id: Mapped[str] = mapped_column(String(64))
    head_sha: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="running")
    degraded: Mapped[list[str]] = mapped_column(JSON, default=list)
    files_scanned: Mapped[list[str]] = mapped_column(JSON, default=list)
    files_skipped: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list)
    est_sent_tokens: Mapped[int] = mapped_column(Integer, default=0)
    est_full_repo_tokens: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_label: Mapped[str] = mapped_column(String(16), default="low")
    decision: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    findings: Mapped[list[FindingRow]] = relationship(back_populates="scan")


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    file: Mapped[str] = mapped_column(String(512))
    line: Mapped[int] = mapped_column(Integer)
    cwe: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float)
    source: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    exploit: Mapped[str | None] = mapped_column(Text, nullable=True)
    fix: Mapped[str | None] = mapped_column(Text, nullable=True)
    comment_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class LLMCall(Base):
    __tablename__ = "llm_calls"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), index=True)
    tier: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16))            # detector_a | detector_b | judge
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class VCSCall(Base):
    __tablename__ = "vcs_calls"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(16))
    op: Mapped[str] = mapped_column(String(48))
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class DialogTurn(Base):
    __tablename__ = "dialog_turns"

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    repo_slug: Mapped[str] = mapped_column(String(255))
    pr_id: Mapped[str] = mapped_column(String(64))
    thread_id: Mapped[str] = mapped_column(String(128), index=True)
    finding_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    turn: Mapped[int] = mapped_column(Integer, default=1)
    author: Mapped[str] = mapped_column(String(128), default="")
    question: Mapped[str] = mapped_column(Text, default="")
    answer: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Feedback(Base):
    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), index=True)
    finding_fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(16))            # helpful | false_positive
    author: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AdminAudit(Base):
    __tablename__ = "admin_audit"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255))
    before: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    after: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class KnowledgeEntry(Base):
    """Security Knowledge Base — confirmed findings indexed for similarity recall.

    Powers "this is similar to a finding in PR #142". The embedding is stored as a
    JSON float array (portable across Postgres/SQLite); similarity is cosine over a
    repo-scoped, recency-bounded candidate set. For very large installs the embedding
    column can be migrated to a native pgvector index without changing the query API.
    """

    __tablename__ = "knowledge_entries"
    __table_args__ = (
        UniqueConstraint("repo_slug", "fingerprint", name="uq_kb_repo_fingerprint"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    repo_slug: Mapped[str] = mapped_column(String(255), index=True)
    provider: Mapped[str] = mapped_column(String(16))
    pr_id: Mapped[str] = mapped_column(String(64))
    scan_id: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    cwe: Mapped[str | None] = mapped_column(String(16), nullable=True)
    severity: Mapped[str] = mapped_column(String(16))
    file: Mapped[str] = mapped_column(String(512))
    title: Mapped[str] = mapped_column(Text)
    snippet: Mapped[str] = mapped_column(Text, default="")
    embedding: Mapped[list[float]] = mapped_column(JSON, default=list)
    confirmed: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
