"""add user.language column

Revision ID: 0002_user_language
Revises: 0001_initial
Create Date: 2026-05-16

Persists the user's preferred interface and AI-response language (ru/en) so it
syncs across web sessions, VS Code extension, and scan/chat backends.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_user_language"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = [c["name"] for c in insp.get_columns("users")]
    if "language" not in cols:
        op.add_column(
            "users",
            sa.Column(
                "language",
                sa.String(length=8),
                nullable=False,
                server_default="ru",
            ),
        )


def downgrade() -> None:
    op.drop_column("users", "language")
