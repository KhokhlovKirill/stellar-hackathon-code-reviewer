"""Async engine + session factory. One engine per process."""

from __future__ import annotations

import functools
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aegis.config import get_settings


@functools.lru_cache(maxsize=1)
def _engine():  # type: ignore[no-untyped-def]
    return create_async_engine(
        get_settings().database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )


@functools.lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(_engine(), expire_on_commit=False, class_=AsyncSession)


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    sm = get_sessionmaker()
    async with sm() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def ping() -> bool:
    """Readiness probe — true if the DB answers."""
    try:
        async with get_sessionmaker()() as s:
            await s.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
