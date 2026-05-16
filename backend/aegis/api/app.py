"""FastAPI application factory.

Exposes health/readiness/metrics and (Phase 1+) webhook + admin routes.
Importing this module must not require a live DB/Redis (so unit tests and
`--help` work offline); connectivity is checked lazily in /readyz.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse

from aegis import __version__
from aegis.config import get_config, get_settings
from aegis.obs import get_logger, metrics, setup_logging

log = get_logger("aegis.api")


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    setup_logging(get_settings().log_level)
    log.info("startup", version=__version__, env=get_settings().env)
    yield
    log.info("shutdown")


def create_app() -> FastAPI:
    app = FastAPI(title="Aegis", version=__version__, lifespan=_lifespan)

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        from aegis.db import ping as db_ping

        checks = {"db": await db_ping()}
        try:
            import redis.asyncio as aioredis

            r = cast(
                aioredis.Redis,
                aioredis.from_url(get_settings().redis_url),  # type: ignore[no-untyped-call]
            )
            checks["redis"] = bool(await r.ping())
            await r.aclose()
        except Exception:
            checks["redis"] = False
        ok = all(checks.values())
        return JSONResponse({"ready": ok, "checks": checks}, status_code=200 if ok else 503)

    @app.get("/metrics")
    async def prometheus() -> Response:
        if not get_config().observability.prometheus_enabled:
            return Response(status_code=404)
        return Response(metrics.render(), media_type="text/plain; version=0.0.4")

    # Phase 1+ routers (import lazily; absence must not break health/metrics).
    try:
        from aegis.api.webhooks import router as webhooks_router

        app.include_router(webhooks_router)
    except ImportError:
        log.warning("webhooks_router_unavailable", phase="will be added in Phase 1")

    try:
        from aegis.api.admin import router as admin_router

        app.include_router(admin_router)
    except ImportError:
        log.warning("admin_router_unavailable", phase="will be added in Phase 8")

    try:
        from aegis.web import router as web_router

        app.include_router(web_router)
    except ImportError:
        log.warning("web_router_unavailable", phase="server-rendered control plane")

    try:
        from aegis.api.extension import router as ext_router

        app.include_router(ext_router)
    except ImportError:
        log.warning("ext_router_unavailable")

    return app


app = create_app()
