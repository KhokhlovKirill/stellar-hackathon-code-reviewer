"""Persistence: SQLAlchemy 2.0 async models, session factory, Alembic migrations."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession

from aegis.db.session import (
    close_db,
    get_db,
    get_engine,
    get_session_factory,
    init_db,
)


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    """Context manager for scripts that use `async with get_session()`."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def ping() -> bool:
    """Return True if the database accepts connections."""
    from sqlalchemy import text

    engine = get_engine()
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return True


__all__ = [
    "close_db",
    "get_db",
    "get_engine",
    "get_session",
    "get_session_factory",
    "init_db",
    "ping",
]
