"""Job enqueue helpers (Arq). The API process enqueues; the worker consumes.

Per-repo serialization + stale-commit cancellation (config.queue.per_repo_concurrency)
is enforced via a per-repo "active head" key: when a newer head_sha arrives we mark
older scans superseded so the worker can short-circuit them (docs/03 §2.2).
"""

from __future__ import annotations

import functools

from arq import create_pool
from arq.connections import RedisSettings

from aegis.config import get_settings
from aegis.obs import metrics
from aegis.redispool import redis
from aegis.schemas import WebhookEvent


@functools.lru_cache(maxsize=1)
def _redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)


async def enqueue_scan(scan_id: str, ev: WebhookEvent) -> None:
    # Stash the event so the worker can rehydrate it by scan_id.
    await redis().set(f"aegis:scan:{scan_id}:event", ev.model_dump_json(), ex=86_400)
    # Mark this head_sha as the active one for the repo+pr; older scans see a
    # mismatch and abort early (cancel stale work on rapid pushes).
    active_key = f"aegis:active:{ev.provider.value}:{ev.repo_external_id}:{ev.pr_id}"
    await redis().set(active_key, ev.head_sha or "", ex=86_400)
    pool = await create_pool(_redis_settings())
    try:
        await pool.enqueue_job("run_scan", scan_id)
        metrics.queue_depth.inc()
    finally:
        await pool.aclose()


async def enqueue_dialog(event_json: str) -> None:
    pool = await create_pool(_redis_settings())
    try:
        await pool.enqueue_job("run_dialog", event_json)
    finally:
        await pool.aclose()


async def is_stale(provider: str, repo_external_id: str, pr_id: str, head_sha: str) -> bool:
    """True if a newer commit superseded this scan (worker should abort)."""
    active = await redis().get(f"aegis:active:{provider}:{repo_external_id}:{pr_id}")
    return active is not None and active != head_sha
