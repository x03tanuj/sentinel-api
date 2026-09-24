"""Target API main FastAPI application entrypoint.

Wires up routers, declares bearerAuth security scheme, and exposes health
and state reset endpoints for testing and automated scanning.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.data import reset_data
from app.routes_admin import router as admin_router
from app.routes_auth import router as auth_router
from app.routes_orders import router as orders_router
from app.routes_products import router as products_router
from app.routes_reports import router as reports_router
from app.routes_users import router as users_router
from app.schemas import HealthResponse, ResetResponse

app = FastAPI(
    title="Target API (Vulnerable Demo)",
    description=(
        "Intentionally vulnerable sandbox API serving as a verification target "
        "for the SentinelAPI security scanner. Switch between vulnerable (SECURE=false) "
        "and hardened (SECURE=true) modes via environment variable."
    ),
    version="1.0.0",
)

# Enable CORS for frontend and scanner integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register endpoint routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(orders_router)
app.include_router(admin_router)
app.include_router(reports_router)
app.include_router(products_router)


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health Check",
    description="Reports service operational status.",
    operation_id="healthcheck",
    tags=["System"],
)
def health() -> HealthResponse:
    """Service health check endpoint."""
    return HealthResponse(status="ok")


# DEMO / TEST HELPER ONLY:
# Resets in-memory users, orders, and products to initial seed values
# and wipes all rate-limiting sliding-window counters.
@app.post(
    "/_reset",
    response_model=ResetResponse,
    summary="Reset Seed Data (Demo / Test Helper Only)",
    description="Resets all in-memory database records to original seed state and clears rate limits.",
    operation_id="reset_state",
    tags=["System"],
)
def reset_state() -> ResetResponse:
    """Reset data store and rate limit state for reproducible testing."""
    reset_data()
    return ResetResponse(status="reset")
