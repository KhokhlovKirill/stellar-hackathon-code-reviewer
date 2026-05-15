"""SQLAlchemy async engine and session factory."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from aegis.config import settings
from aegis.observability.logging import get_logger

log = get_logger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _create_engine() -> AsyncEngine:
    return create_async_engine(
        settings.database_url,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout,
        pool_pre_ping=True,
        echo=settings.is_development,
    )


async def init_db() -> None:
    """Run migrations, create engine, and verify connection."""
    global _engine, _session_factory

    from aegis.db.migrate import run_migrations

    await asyncio.to_thread(run_migrations)

    _engine = _create_engine()
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)
    # Verify connectivity
    async with _engine.connect() as conn:
        await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
    log.info("db.connected", url=settings.database_url.split("@")[-1])


async def close_db() -> None:
    """Dispose the connection pool."""
    global _engine
    if _engine:
        await _engine.dispose()
        log.info("db.disconnected")


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("Database not initialised — call init_db() first")
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    if _session_factory is None:
        raise RuntimeError("Database not initialised — call init_db() first")
    return _session_factory


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency that yields a session and commits/rolls back."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
