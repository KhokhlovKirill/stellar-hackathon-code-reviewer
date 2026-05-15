"""Arq WorkerSettings — entry point for the background worker process."""

from __future__ import annotations

import asyncio
import logging

from arq.connections import RedisSettings
from arq.worker import create_worker

from aegis.observability.logging import setup_logging  # alias of configure_logging
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
    from aegis.worker.graph_worker import ARQ_QUEUE_NAME, run_graph_scan

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
        queue_name = ARQ_QUEUE_NAME
        log_results = True

    return WorkerSettings


# Arq CLI entry point
WorkerSettings = get_worker_settings()


if __name__ == "__main__":
    """Run the worker directly: python -m aegis.worker.main"""

    async def main():
        setup_logging()
        worker = create_worker(WorkerSettings)
        await worker.async_run()

    asyncio.run(main())
