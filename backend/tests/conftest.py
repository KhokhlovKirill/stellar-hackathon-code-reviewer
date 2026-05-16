from __future__ import annotations

import asyncio
import warnings
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def close_idle_event_loop() -> Iterator[None]:
    yield
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            loop = asyncio.get_event_loop()
    except RuntimeError:
        return
    if not loop.is_running() and not loop.is_closed():
        loop.close()
        asyncio.set_event_loop(None)
