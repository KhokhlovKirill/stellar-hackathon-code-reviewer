"""initial baseline — create all tables from ORM metadata

Revision ID: 0001_initial
Revises:
Create Date: 2026-05-15

Baseline migration: materializes the full schema (aegis.db.models.Base). Subsequent
schema changes use `alembic revision --autogenerate` against this baseline.
"""

from __future__ import annotations

from collections.abc import Sequence

from aegis.db.models import Base
from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
