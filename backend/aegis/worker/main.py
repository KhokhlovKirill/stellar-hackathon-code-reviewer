"""Arq worker settings + job entrypoints.

`run_scan` and `run_dialog` are filled in by later phases (pipeline). Here we wire
the queue, retries/backoff, and Redis so Gate 0 (worker boots, connects) is green.
"""

from __future__ import annotations

from typing import Any, ClassVar

from arq.connections import RedisSettings

from aegis.config import get_config, get_settings
from aegis.obs import get_logger, setup_logging

log = get_logger("aegis.worker")


async def run_scan(ctx: dict[str, Any], scan_id: str) -> None:
    """Pipeline entrypoint (Phase 1+ wires fetch→filter→detect→render)."""
    from aegis.pipeline.runner import run_scan_pipeline

    await run_scan_pipeline(scan_id)


async def run_dialog(ctx: dict[str, Any], event_json: str) -> None:
    """Dialog follow-up entrypoint (Phase 7)."""
    from aegis.pipeline.dialog import handle_dialog_event

    await handle_dialog_event(event_json)


async def _startup(ctx: dict[str, Any]) -> None:
    setup_logging(get_settings().log_level)
    log.info("worker_startup")


async def _shutdown(ctx: dict[str, Any]) -> None:
    log.info("worker_shutdown")


class WorkerSettings:
    functions: ClassVar = [run_scan, run_dialog]
    on_startup = _startup
    on_shutdown = _shutdown
    redis_settings = RedisSettings.from_dsn(get_settings().redis_url)
    max_tries = get_config().queue.max_retries
    retry_delay = get_config().queue.retry_backoff_base_seconds
    job_timeout = 600
    health_check_interval = 30
