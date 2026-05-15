<<<<<<< Updated upstream
"""Alembic env — async engine, target metadata = aegis.db.models.Base.

DB URL comes from Settings (env), not alembic.ini, so secrets stay out of config files.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from sqlalchemy.ext.asyncio import create_async_engine

from aegis.config import get_settings
from aegis.db.models import Base
from alembic import context

config = context.config
=======
"""Alembic environment — uses sync SQLAlchemy URL for migrations."""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Load application models so Alembic can autogenerate migrations
from aegis.db.models import Base  # noqa: F401
from aegis.config import settings

config = context.config

# Use sync URL for Alembic (asyncpg doesn't work with Alembic directly)
sync_url = settings.database_sync_url
config.set_main_option("sqlalchemy.url", sync_url)

>>>>>>> Stashed changes
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


<<<<<<< Updated upstream
def _url() -> str:
    return get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
=======
def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
>>>>>>> Stashed changes
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


<<<<<<< Updated upstream
def _do_run(connection) -> None:  # type: ignore[no-untyped-def]
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_async_engine(_url(), poolclass=None)
    async with engine.connect() as connection:
        await connection.run_sync(_do_run)
    await engine.dispose()
=======
def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
>>>>>>> Stashed changes


if context.is_offline_mode():
    run_migrations_offline()
else:
<<<<<<< Updated upstream
    asyncio.run(run_migrations_online())
=======
    run_migrations_online()
>>>>>>> Stashed changes
