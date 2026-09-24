"""SentinelAPI main FastAPI application entrypoint.

Provides core health checks, scope disclosure endpoints, scan orchestration
routes, and CORS middleware for development and UI integration.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.routes.ai import router as ai_router
from app.routes.scans import router as scans_router
from app.scan_manager import ScanManager
from app.store import JsonSnapshotStore

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure a FastAPI application instance with lifespan management."""
    active_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # 1. Startup: Initialize storage and scan orchestration manager
        store = JsonSnapshotStore(
            data_dir=active_settings.DATA_DIR,
            max_stored=active_settings.MAX_STORED_SCANS,
        )
        await store.mark_interrupted_on_startup()

        manager = ScanManager(store=store, settings=active_settings)

        app.state.store = store
        app.state.scan_manager = manager
        app.state.settings = active_settings

        if active_settings.SENTINEL_API_KEY is None:
            logger.warning(
                "Scanner API is unauthenticated (SENTINEL_API_KEY is not configured). "
                "Bind to localhost only to prevent unauthorized scan execution!"
            )

        yield

        # 2. Shutdown: Cancel ongoing scans and flush storage
        await manager.shutdown()

    app = FastAPI(
        title="SentinelAPI",
        description="API security scanner for authorization and data-exposure vulnerabilities.",
        version="0.1.0",
        lifespan=lifespan,
    )

    if settings is not None:
        app.dependency_overrides[get_settings] = lambda: active_settings

    # CORS configuration restricted to authorized origins and methods
    app.add_middleware(
        CORSMiddleware,
        allow_origins=active_settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", "X-API-Key"],
    )

    # Sanitize validation error responses to prevent echoing raw credential inputs
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        sanitized_errors = []
        for err in exc.errors():
            clean = {k: v for k, v in err.items() if k != "input"}
            sanitized_errors.append(clean)
        return JSONResponse(status_code=422, content={"detail": sanitized_errors})

    # Include Scan Orchestration Router
    app.include_router(scans_router)

    # Include AI Analyst Router
    app.include_router(ai_router)

    # Public Unauthenticated Routes
    @app.get("/health", tags=["system"], operation_id="health_check")
    def health() -> dict[str, str]:
        """Healthcheck endpoint reporting service operational status."""
        return {"status": "ok", "service": "sentinelapi"}

    @app.get("/scope", tags=["system"], operation_id="get_scope")
    def get_scope() -> dict[str, Any]:
        """Return the list of explicitly allow-listed scan target hosts."""
        return {"allowed_hosts": active_settings.ALLOWED_HOSTS}

    return app


# Default application instance for Uvicorn and CLI runners
app = create_app()
