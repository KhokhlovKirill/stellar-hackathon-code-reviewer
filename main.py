"""FastAPI application entry-point with lifespan management."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

import orjson
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from aegis.config import settings
from aegis.db.session import init_db, close_db
from aegis.observability.logging import configure_logging, get_logger
from aegis.observability.metrics import setup_metrics
from aegis.observability.tracing import setup_tracing

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup / shutdown lifecycle."""
    configure_logging()
    setup_tracing()
    setup_metrics()

    log.info("aegis.startup", env=settings.app_env, version="2.0.0")

    await init_db()

    yield

    await close_db()
    log.info("aegis.shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Aegis DevSecOps API",
        description="LangGraph-orchestrated automated PR security review platform",
        version="2.0.0",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        lifespan=lifespan,
        default_response_class=_OrjsonResponse,
    )

    # ── CORS ─────────────────────────────────────────────────────────────────
    # When ``allow_origins=["*"]`` is set together with ``allow_credentials=True``
    # browsers reject the response — so we keep credentials only in non-wildcard
    # production setups (where origins are configured explicitly).
    if settings.is_development:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    else:
        # In production deployments, restrict origins externally (e.g. via nginx)
        # or override here. Default to a safe no-CORS config.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # ── Request timing middleware ─────────────────────────────────────────────
    @app.middleware("http")
    async def add_process_time(request: Request, call_next):  # noqa: ANN001
        start = time.perf_counter()
        response: Response = await call_next(request)
        response.headers["X-Process-Time"] = f"{(time.perf_counter() - start) * 1000:.1f}ms"
        return response

    # ── Routes ────────────────────────────────────────────────────────────────
    from aegis.api.webhooks import router as webhooks_router
    from aegis.api.admin import router as admin_router
    from aegis.api.auth import router as auth_router

    # Each router sets its path prefix once (avoid /api/api/... duplication).
    app.include_router(webhooks_router)
    app.include_router(auth_router, prefix="/api/auth")
    app.include_router(admin_router)

    # ── Health / metrics ─────────────────────────────────────────────────────
    @app.get("/health", include_in_schema=False)
    async def health() -> dict:
        return {"status": "ok", "version": "2.0.0"}

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


class _OrjsonResponse(JSONResponse):
    media_type = "application/json"

    def render(self, content: object) -> bytes:
        return orjson.dumps(content)


app = create_app()
