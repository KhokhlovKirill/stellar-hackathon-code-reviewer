"""dedupe repo_secrets + unique (repo_id, kind)

Revision ID: 0003_repo_secret_unique
Revises: 0002_user_language
Create Date: 2026-05-16

Repos accumulated one RepoSecret row per (re)connect. scalar_one_or_none()
over them raised MultipleResultsFound and 500'd the project page / PR list.
This migration removes existing duplicates (keeping the newest per
repo_id+kind) and adds a unique constraint so the invariant is enforced by
the database, not just by application code.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_repo_secret_unique"
down_revision: str | None = "0002_user_language"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    # 1. Collapse duplicates, keeping the most recent row per (repo_id, kind).
    bind.execute(
        sa.text(
            """
            DELETE FROM repo_secrets rs
            USING (
                SELECT id,
                       ROW_NUMBER() OVER (
                           PARTITION BY repo_id, kind
                           ORDER BY created_at DESC, id DESC
                       ) AS rn
                FROM repo_secrets
            ) ranked
            WHERE rs.id = ranked.id AND ranked.rn > 1
            """
        )
    )
    # 2. Enforce the invariant going forward.
    insp = sa.inspect(bind)
    existing = {uc["name"] for uc in insp.get_unique_constraints("repo_secrets")}
    if "uq_repo_secret_repo_kind" not in existing:
        op.create_unique_constraint(
            "uq_repo_secret_repo_kind", "repo_secrets", ["repo_id", "kind"]
        )


def downgrade() -> None:
    op.drop_constraint(
        "uq_repo_secret_repo_kind", "repo_secrets", type_="unique"
    )
