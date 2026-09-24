"""SentinelAPI main FastAPI application entrypoint.

Provides core health checks, scope disclosure endpoints, and CORS middleware
for development and UI integration.
"""

from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings

app = FastAPI(
    title="SentinelAPI",
    description="API security scanner for authorization and data-exposure vulnerabilities.",
    version="0.1.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    """Healthcheck endpoint reporting service operational status."""
    return {"status": "ok", "service": "sentinelapi"}


@app.get("/scope")
def get_scope() -> dict[str, Any]:
    """Return the list of explicitly allow-listed scan target hosts."""
    settings = get_settings()
    return {"allowed_hosts": settings.ALLOWED_HOSTS}
