<<<<<<< Updated upstream
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
=======
"""Arq WorkerSettings — entry point for the background worker process."""

from __future__ import annotations

import asyncio
import logging

from arq import Worker
from arq.connections import RedisSettings

from aegis.observability.logging import setup_logging
from aegis.observability.metrics import setup_metrics

log = logging.getLogger(__name__)


async def startup(ctx: dict) -> None:
    """Worker startup: initialize DB connection pool and observability."""
    setup_logging()
    setup_metrics()

    log.info("worker.startup")

    # Initialize database
    from aegis.db.session import init_db
    await init_db()

    log.info("worker.ready")


async def shutdown(ctx: dict) -> None:
    """Worker shutdown: close DB connections."""
    from aegis.db.session import close_db
    await close_db()
    log.info("worker.shutdown")


async def on_job_start(ctx: dict) -> None:
    """Called before each job execution."""
    job_id = ctx.get("job_id", "unknown")
    log.info("worker.job_start", extra={"job_id": job_id})


async def on_job_end(ctx: dict) -> None:
    """Called after each job execution."""
    job_id = ctx.get("job_id", "unknown")
    log.info("worker.job_end", extra={"job_id": job_id})


def get_worker_settings():
    """Build and return Arq WorkerSettings."""
    from aegis.config import get_settings
    from aegis.worker.graph_worker import run_graph_scan

    settings = get_settings()

    redis = RedisSettings.from_dsn(settings.redis_url)

    class WorkerSettings:
        functions = [run_graph_scan]
        on_startup = startup
        on_shutdown = shutdown
        on_job_start = on_job_start
        on_job_end = on_job_end
        redis_settings = redis
        max_jobs = settings.worker_max_jobs
        job_timeout = settings.worker_job_timeout
        keep_result = 3600  # Keep result for 1 hour
        max_tries = 2  # Retry once on failure
        retry_jobs = True
        allow_abort_jobs = True
        queue_name = "aegis:queue"
        log_results = True

    return WorkerSettings


# Arq CLI entry point
WorkerSettings = get_worker_settings()


if __name__ == "__main__":
    """Run the worker directly: python -m aegis.worker.main"""
    import arq

    async def main():
        setup_logging()
        worker = Worker(WorkerSettings)
        await worker.async_run()

    asyncio.run(main())
>>>>>>> Stashed changes
