"""Initial schema with all Aegis tables and pgvector extension.

Revision ID: 001
Revises:
Create Date: 2026-05-15
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Enable pgvector
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    # ── repositories ──────────────────────────────────────────────────────────
    op.create_table(
        "repositories",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("slug", sa.String(255), nullable=False),
        sa.Column("url", sa.String(512), nullable=False),
        sa.Column("token_encrypted", sa.Text),
        sa.Column("webhook_secret_encrypted", sa.Text),
        sa.Column("settings_json", postgresql.JSONB, server_default="{}"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("provider", "slug", name="uq_repo_provider_slug"),
    )

    # ── pull_requests ─────────────────────────────────────────────────────────
    op.create_table(
        "pull_requests",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("repo_id", sa.BigInteger, sa.ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False),
        sa.Column("pr_number", sa.Integer, nullable=False),
        sa.Column("pr_title", sa.String(512)),
        sa.Column("author", sa.String(255)),
        sa.Column("base_branch", sa.String(255)),
        sa.Column("head_branch", sa.String(255)),
        sa.Column("pr_url", sa.String(512)),
        sa.Column("scan_id", sa.String(64)),
        sa.Column("risk_score", sa.Integer, server_default="0"),
        sa.Column("risk_label", sa.String(16)),
        sa.Column("status", sa.String(32), server_default="pending"),
        sa.Column("findings_count", sa.Integer, server_default="0"),
        sa.Column("critical_count", sa.Integer, server_default="0"),
        sa.Column("high_count", sa.Integer, server_default="0"),
        sa.Column("medium_count", sa.Integer, server_default="0"),
        sa.Column("low_count", sa.Integer, server_default="0"),
        sa.Column("summary_comment_id", sa.String(64)),
        sa.Column("analysis_metadata", postgresql.JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("repo_id", "pr_number", name="uq_pr_repo_number"),
    )
    op.create_index("ix_pr_repo_status", "pull_requests", ["repo_id", "status"])
    op.create_index("ix_pr_scan_id", "pull_requests", ["scan_id"])

    # ── findings ──────────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("pr_id", sa.BigInteger, sa.ForeignKey("pull_requests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("file_path", sa.String(512), nullable=False),
        sa.Column("line_number", sa.Integer),
        sa.Column("end_line_number", sa.Integer),
        sa.Column("vuln_type", sa.String(128)),
        sa.Column("cwe", sa.String(32)),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float, server_default="0.8"),
        sa.Column("description", sa.Text),
        sa.Column("fix_snippet", sa.Text),
        sa.Column("source", sa.String(64)),
        sa.Column("fingerprint", sa.String(64)),
        sa.Column("is_suppressed", sa.Boolean, server_default="false"),
        sa.Column("comment_id", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.execute("ALTER TABLE findings ADD COLUMN embedding vector(1536)")
    op.create_index("ix_finding_pr_severity", "findings", ["pr_id", "severity"])
    op.create_index("ix_finding_fingerprint", "findings", ["fingerprint"])

    # ── llm_logs ──────────────────────────────────────────────────────────────
    op.create_table(
        "llm_logs",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("pr_id", sa.BigInteger, sa.ForeignKey("pull_requests.id", ondelete="SET NULL")),
        sa.Column("scan_id", sa.String(64)),
        sa.Column("model", sa.String(128)),
        sa.Column("prompt", sa.Text, nullable=False),
        sa.Column("response", sa.Text),
        sa.Column("prompt_tokens", sa.Integer, server_default="0"),
        sa.Column("completion_tokens", sa.Integer, server_default="0"),
        sa.Column("total_tokens", sa.Integer, server_default="0"),
        sa.Column("latency_ms", sa.Integer, server_default="0"),
        sa.Column("success", sa.Boolean, server_default="true"),
        sa.Column("error", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── dialogs ───────────────────────────────────────────────────────────────
    op.create_table(
        "dialogs",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("pr_id", sa.BigInteger, sa.ForeignKey("pull_requests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("messages_json", postgresql.JSONB, server_default="[]"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── false_positives ───────────────────────────────────────────────────────
    op.create_table(
        "false_positives",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("repo_id", sa.BigInteger, sa.ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False),
        sa.Column("pattern", sa.String(512), nullable=False),
        sa.Column("directory", sa.String(512)),
        sa.Column("cwe", sa.String(32)),
        sa.Column("count", sa.Integer, server_default="1"),
        sa.Column("auto_suppressed", sa.Boolean, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── graph_executions ──────────────────────────────────────────────────────
    op.create_table(
        "graph_executions",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("pr_id", sa.BigInteger, sa.ForeignKey("pull_requests.id", ondelete="SET NULL")),
        sa.Column("graph_id", sa.String(128)),
        sa.Column("current_node", sa.String(128)),
        sa.Column("status", sa.String(32), server_default="running"),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("interrupted", sa.Boolean, server_default="false"),
        sa.Column("resumed_count", sa.Integer, server_default="0"),
        sa.Column("metadata_json", postgresql.JSONB, server_default="{}"),
    )
    op.create_index("ix_graph_exec_scan_id", "graph_executions", ["scan_id"])

    # ── graph_node_runs ───────────────────────────────────────────────────────
    op.create_table(
        "graph_node_runs",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "graph_execution_id",
            sa.BigInteger,
            sa.ForeignKey("graph_executions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("node_name", sa.String(128), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("duration_ms", sa.Integer, server_default="0"),
        sa.Column("status", sa.String(32), server_default="ok"),
        sa.Column("retries", sa.Integer, server_default="0"),
        sa.Column("error", sa.Text),
        sa.Column("metadata_json", postgresql.JSONB, server_default="{}"),
    )

    # ── human_reviews ─────────────────────────────────────────────────────────
    op.create_table(
        "human_reviews",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.String(64), nullable=False),
        sa.Column("finding_fingerprint", sa.String(64)),
        sa.Column("reviewer", sa.String(255)),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("rationale", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_human_review_scan_id", "human_reviews", ["scan_id"])

    # ── knowledge_base ────────────────────────────────────────────────────────
    op.create_table(
        "knowledge_base",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("repo_id", sa.BigInteger, sa.ForeignKey("repositories.id", ondelete="SET NULL")),
        sa.Column("pr_number", sa.Integer),
        sa.Column("cwe", sa.String(32)),
        sa.Column("vuln_type", sa.String(128)),
        sa.Column("severity", sa.String(16)),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("fix_snippet", sa.Text),
        sa.Column("file_path", sa.String(512)),
        sa.Column("code_snippet", sa.Text),
        sa.Column("frequency", sa.Integer, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.execute("ALTER TABLE knowledge_base ADD COLUMN embedding vector(1536)")

    # ── users ─────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(128), unique=True, nullable=False),
        sa.Column("email", sa.String(256), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(256), nullable=False),
        sa.Column("role", sa.String(32), server_default="viewer"),
        sa.Column("is_active", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # ── LangGraph checkpoint table (LangGraph creates this itself, but we declare it) ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS graph_checkpoints (
            thread_id VARCHAR(128),
            checkpoint_ns VARCHAR(128) DEFAULT '',
            checkpoint_id VARCHAR(128),
            parent_checkpoint_id VARCHAR(128),
            type VARCHAR(32),
            checkpoint JSONB,
            metadata JSONB DEFAULT '{}',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id)
        )
    """)

    # HNSW indexes (non-concurrent — CONCURRENTLY cannot run inside Alembic's transaction)
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_findings_embedding "
        "ON findings USING hnsw (embedding vector_cosine_ops)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_kb_embedding "
        "ON knowledge_base USING hnsw (embedding vector_cosine_ops)"
    )


def downgrade() -> None:
    op.drop_table("users")
    op.drop_table("knowledge_base")
    op.drop_table("human_reviews")
    op.drop_table("graph_node_runs")
    op.drop_table("graph_executions")
    op.drop_table("false_positives")
    op.drop_table("dialogs")
    op.drop_table("llm_logs")
    op.drop_table("findings")
    op.drop_table("pull_requests")
    op.drop_table("repositories")
    op.execute("DROP TABLE IF EXISTS graph_checkpoints")
    op.execute("DROP EXTENSION IF EXISTS vector")
