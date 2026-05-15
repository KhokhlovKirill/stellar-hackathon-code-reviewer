"""SQLAlchemy ORM models for the Aegis platform."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ── Enums ─────────────────────────────────────────────────────────────────────


class ProviderEnum(str, enum.Enum):
    github = "github"
    gitlab = "gitlab"
    bitbucket = "bitbucket"


class SeverityEnum(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class PRStatusEnum(str, enum.Enum):
    pending = "pending"
    analyzing = "analyzing"
    passed = "passed"
    blocked = "blocked"
    error = "error"


class GraphStatusEnum(str, enum.Enum):
    running = "running"
    completed = "completed"
    failed = "failed"
    interrupted = "interrupted"
    resumed = "resumed"


class HumanDecisionEnum(str, enum.Enum):
    approve = "approve"
    reject = "reject"
    suppress = "suppress"
    escalate = "escalate"
    rerun = "rerun"


def _str_enum_column(enum_cls: type[enum.Enum], *, length: int | None = None, **kwargs: Any):
    """VARCHAR-backed enum — matches Alembic migrations (no native PG ENUM types)."""
    return mapped_column(
        Enum(
            enum_cls,
            native_enum=False,
            length=length,
            values_callable=lambda obj: [member.value for member in obj],
        ),
        **kwargs,
    )


# ── Models ────────────────────────────────────────────────────────────────────


class Repository(Base):
    """A Git repository connected to Aegis."""

    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    provider: Mapped[str] = _str_enum_column(ProviderEnum, length=32, nullable=False)
    slug: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    # Fernet-encrypted provider token
    token_encrypted: Mapped[str | None] = mapped_column(Text)
    # Fernet-encrypted webhook secret
    webhook_secret_encrypted: Mapped[str | None] = mapped_column(Text)
    # JSON: {block_threshold, ignored_dirs, semgrep_rules, ...}
    settings_json: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}")
    is_active: Mapped[bool] = mapped_column(Boolean, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    pull_requests: Mapped[list[PullRequest]] = relationship(back_populates="repository", cascade="all, delete-orphan")
    false_positives: Mapped[list[FalsePositive]] = relationship(back_populates="repository")

    __table_args__ = (UniqueConstraint("provider", "slug", name="uq_repo_provider_slug"),)

    # API / webhook aliases (slug is org/repo or group/project path)
    @property
    def full_name(self) -> str:
        return self.slug

    @property
    def access_token(self) -> str | None:
        return self.token_encrypted

    @property
    def webhook_secret(self) -> str | None:
        return self.webhook_secret_encrypted

    @property
    def active(self) -> bool:
        return self.is_active


def repository_url(provider: str, slug: str) -> str:
    """Canonical repo URL for provider + slug (e.g. hackathon4/chocolate)."""
    match provider:
        case "github":
            return f"https://github.com/{slug}"
        case "gitlab":
            from aegis.config import get_settings

            origin = get_settings().gitlab_web_origin
            return f"{origin}/{slug}"
        case "bitbucket":
            return f"https://bitbucket.org/{slug}"
        case _:
            return slug


class PullRequest(Base):
    """Record of an analysed Pull/Merge Request."""

    __tablename__ = "pull_requests"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    repo_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("repositories.id", ondelete="CASCADE"))
    pr_number: Mapped[int] = mapped_column(Integer, nullable=False)
    pr_title: Mapped[str | None] = mapped_column(String(512))
    author: Mapped[str | None] = mapped_column(String(255))
    base_branch: Mapped[str | None] = mapped_column(String(255))
    head_branch: Mapped[str | None] = mapped_column(String(255))
    pr_url: Mapped[str | None] = mapped_column(String(512))
    scan_id: Mapped[str | None] = mapped_column(String(64), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, server_default="0")
    risk_label: Mapped[str | None] = mapped_column(String(16))  # green/yellow/red
    status: Mapped[str] = _str_enum_column(PRStatusEnum, length=32, server_default=PRStatusEnum.pending.value)
    findings_count: Mapped[int] = mapped_column(Integer, server_default="0")
    critical_count: Mapped[int] = mapped_column(Integer, server_default="0")
    high_count: Mapped[int] = mapped_column(Integer, server_default="0")
    medium_count: Mapped[int] = mapped_column(Integer, server_default="0")
    low_count: Mapped[int] = mapped_column(Integer, server_default="0")
    summary_comment_id: Mapped[str | None] = mapped_column(String(64))
    analysis_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    repository: Mapped[Repository] = relationship(back_populates="pull_requests")
    findings: Mapped[list[Finding]] = relationship(back_populates="pull_request", cascade="all, delete-orphan")
    llm_logs: Mapped[list[LLMLog]] = relationship(back_populates="pull_request", cascade="all, delete-orphan")
    dialogs: Mapped[list[Dialog]] = relationship(back_populates="pull_request", cascade="all, delete-orphan")
    graph_executions: Mapped[list[GraphExecution]] = relationship(back_populates="pull_request")

    __table_args__ = (
        UniqueConstraint("repo_id", "pr_number", name="uq_pr_repo_number"),
        Index("ix_pr_repo_status", "repo_id", "status"),
    )


class Finding(Base):
    """A single security finding within a PR analysis."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    pr_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("pull_requests.id", ondelete="CASCADE"))
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    line_number: Mapped[int | None] = mapped_column(Integer)
    end_line_number: Mapped[int | None] = mapped_column(Integer)
    vuln_type: Mapped[str | None] = mapped_column(String(128))
    cwe: Mapped[str | None] = mapped_column(String(32))  # e.g. "CWE-89"
    severity: Mapped[str] = _str_enum_column(SeverityEnum, length=16, nullable=False)
    confidence: Mapped[float] = mapped_column(server_default="0.8")
    description: Mapped[str | None] = mapped_column(Text)
    fix_snippet: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str | None] = mapped_column(String(64))  # semgrep/bandit/gitleaks/llm/judge
    fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)
    # pgvector column for semantic similarity
    embedding: Mapped[Any] = mapped_column(Vector(1536), nullable=True)
    is_suppressed: Mapped[bool] = mapped_column(Boolean, server_default="false")
    comment_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    pull_request: Mapped[PullRequest] = relationship(back_populates="findings")

    __table_args__ = (Index("ix_finding_pr_severity", "pr_id", "severity"),)


class LLMLog(Base):
    """Full audit log of every LLM request/response."""

    __tablename__ = "llm_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    pr_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("pull_requests.id", ondelete="SET NULL"))
    scan_id: Mapped[str | None] = mapped_column(String(64))
    model: Mapped[str | None] = mapped_column(String(128))
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    response: Mapped[str | None] = mapped_column(Text)
    prompt_tokens: Mapped[int] = mapped_column(Integer, server_default="0")
    completion_tokens: Mapped[int] = mapped_column(Integer, server_default="0")
    total_tokens: Mapped[int] = mapped_column(Integer, server_default="0")
    latency_ms: Mapped[int] = mapped_column(Integer, server_default="0")
    success: Mapped[bool] = mapped_column(Boolean, server_default="true")
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    pull_request: Mapped[PullRequest | None] = relationship(back_populates="llm_logs")


class Dialog(Base):
    """ChatOps session — conversation history for a PR."""

    __tablename__ = "dialogs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    pr_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("pull_requests.id", ondelete="CASCADE"))
    # JSON array of {role, content, timestamp}
    messages_json: Mapped[list[dict]] = mapped_column(JSONB, server_default="[]")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    pull_request: Mapped[PullRequest] = relationship(back_populates="dialogs")


class FalsePositive(Base):
    """Accumulated false-positive patterns reported by developers."""

    __tablename__ = "false_positives"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    repo_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("repositories.id", ondelete="CASCADE"))
    pattern: Mapped[str] = mapped_column(String(512), nullable=False)
    directory: Mapped[str | None] = mapped_column(String(512))
    cwe: Mapped[str | None] = mapped_column(String(32))
    count: Mapped[int] = mapped_column(Integer, server_default="1")
    # When count >= 3 the pattern is auto-suppressed
    auto_suppressed: Mapped[bool] = mapped_column(Boolean, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    repository: Mapped[Repository] = relationship(back_populates="false_positives")


class GraphExecution(Base):
    """Records a single LangGraph execution for audit and resume."""

    __tablename__ = "graph_executions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    pr_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("pull_requests.id", ondelete="SET NULL"))
    graph_id: Mapped[str | None] = mapped_column(String(128))
    current_node: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = _str_enum_column(
        GraphStatusEnum, length=32, server_default=GraphStatusEnum.running.value
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    interrupted: Mapped[bool] = mapped_column(Boolean, server_default="false")
    resumed_count: Mapped[int] = mapped_column(Integer, server_default="0")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}")

    pull_request: Mapped[PullRequest | None] = relationship(back_populates="graph_executions")
    node_runs: Mapped[list[GraphNodeRun]] = relationship(back_populates="graph_execution", cascade="all, delete-orphan")


class GraphNodeRun(Base):
    """Duration and status of each individual graph node execution."""

    __tablename__ = "graph_node_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    graph_execution_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("graph_executions.id", ondelete="CASCADE")
    )
    node_name: Mapped[str] = mapped_column(String(128), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int] = mapped_column(Integer, server_default="0")
    status: Mapped[str] = mapped_column(String(32), server_default="ok")
    retries: Mapped[int] = mapped_column(Integer, server_default="0")
    error: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}")

    graph_execution: Mapped[GraphExecution] = relationship(back_populates="node_runs")


class HumanReview(Base):
    """Record of a human security-lead decision in HITL flow."""

    __tablename__ = "human_reviews"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    finding_fingerprint: Mapped[str | None] = mapped_column(String(64))
    reviewer: Mapped[str | None] = mapped_column(String(255))
    decision: Mapped[str] = _str_enum_column(HumanDecisionEnum, length=32, nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class KnowledgeBase(Base):
    """Semantic store for historical vulnerability findings (pgvector)."""

    __tablename__ = "knowledge_base"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    repo_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("repositories.id", ondelete="SET NULL"))
    pr_number: Mapped[int | None] = mapped_column(Integer)
    cwe: Mapped[str | None] = mapped_column(String(32))
    vuln_type: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[str | None] = _str_enum_column(SeverityEnum, length=16, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    fix_snippet: Mapped[str | None] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(String(512))
    code_snippet: Mapped[str | None] = mapped_column(Text)
    frequency: Mapped[int] = mapped_column(Integer, server_default="1")
    embedding: Mapped[Any] = mapped_column(Vector(1536), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (Index("ix_kb_embedding", "embedding", postgresql_using="ivfflat"),)


class User(Base):
    """Admin/viewer user for web panel authentication."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(32), server_default="'viewer'")  # admin / viewer
    is_active: Mapped[bool] = mapped_column(Boolean, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# pgvector HNSW indexes for fast ANN search (created in migration)
# CREATE INDEX ON findings USING hnsw (embedding vector_cosine_ops);
# CREATE INDEX ON knowledge_base USING hnsw (embedding vector_cosine_ops);
