"""Apply Alembic migrations (sync — required for schema bootstrap)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from aegis.config import settings
from aegis.observability.logging import get_logger

log = get_logger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def run_migrations() -> None:
    """Upgrade database to head revision."""
    ini_path = _PROJECT_ROOT / "alembic.ini"
    if not ini_path.is_file():
        log.warning("db.migrations_skipped", reason="alembic.ini not found")
        return

    cfg = Config(str(ini_path))
    cfg.set_main_option("sqlalchemy.url", settings.database_sync_url)
    log.info("db.migrations_start")
    command.upgrade(cfg, "head")
    log.info("db.migrations_done")
