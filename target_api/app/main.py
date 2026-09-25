"""Target API main FastAPI application entrypoint.

Wires up routers, declares bearerAuth security scheme, and exposes health
and state reset endpoints for testing and automated scanning.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

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


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index() -> HTMLResponse:
    """Live web interface for the ShopSentinel E-Commerce Portal."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>ShopSentinel - Retail & E-Commerce Network</title>
      <style>
        :root {
          --primary: #3b82f6;
          --bg: #0f172a;
          --card: #1e293b;
          --text: #f8fafc;
          --muted: #94a3b8;
          --accent: #60a5fa;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: #0b0f19; color: var(--text); min-height: 100vh; padding: 2rem 1rem; }
        .container { max-width: 1100px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 2rem; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .brand { display: flex; align-items: center; gap: 0.75rem; }
        .logo-icon { width: 40px; height: 40px; background: var(--accent); border-radius: 8px; display: grid; place-items: center; font-weight: bold; font-size: 1.5rem; color: #0f172a; }
        .badge-live { background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid #3b82f6; padding: 0.35rem 0.75rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.25rem; margin: 2rem 0; }
        .stat-card { background: var(--card); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 1.5rem; }
        .stat-val { font-size: 2rem; font-weight: 800; color: #93c5fd; margin-top: 0.5rem; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-top: 2rem; }
        @media(max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
        .panel { background: var(--card); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 1.5rem; }
        .panel h3 { font-size: 1.25rem; margin-bottom: 1rem; color: var(--muted); border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 0.5rem; }
        .cred-item { background: rgba(0,0,0,0.25); padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 0.75rem; font-family: monospace; font-size: 0.9rem; }
        .tag { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; margin-right: 0.5rem; }
        .tag-user { background: #1e3a8a; color: #dbeafe; border: 1px solid #3b82f6; }
        .tag-admin { background: #581c87; color: #f3e8ff; }
        .btn-link { display: inline-block; background: var(--accent); color: #0f172a; font-weight: 600; padding: 0.6rem 1.2rem; border-radius: 6px; text-decoration: none; margin-top: 1rem; margin-right: 0.5rem; transition: all 0.2s; }
        .btn-link:hover { background: #93c5fd; transform: translateY(-1px); }
        .record-row { border-bottom: 1px solid rgba(255,255,255,0.06); padding: 0.75rem 0; font-size: 0.9rem; }
        .record-row:last-child { border-bottom: none; }
      </style>
    </head>
    <body>
      <div class="container">
        <header class="header">
          <div class="brand">
            <div class="logo-icon">&#x1F6D2;</div>
            <div>
              <h1 style="font-size: 1.5rem; font-weight: 700;">ShopSentinel E-Commerce</h1>
              <p style="font-size: 0.85rem; color: var(--muted);">High-Volume Customer Retail &amp; Logistics API</p>
            </div>
          </div>
          <div>
            <span class="badge-live">&#x25CF; Port 9000 Active</span>
          </div>
        </header>

        <section class="stats">
          <div class="stat-card">
            <div>Catalog Items</div>
            <div class="stat-val">1,850</div>
          </div>
          <div class="stat-card">
            <div>Fulfilled Orders</div>
            <div class="stat-val">28,940</div>
          </div>
          <div class="stat-card">
            <div>Security Toggle</div>
            <div class="stat-val" style="font-size: 1.4rem; color: #f87171;">Vulnerable Mode</div>
          </div>
          <div class="stat-card">
            <div>Service Status</div>
            <div class="stat-val" style="font-size: 1.4rem; color: #34d399;">Online</div>
          </div>
        </section>

        <div class="grid-2">
          <div class="panel">
            <h3>&#x1F511; Demo Test Credentials</h3>
            <p style="font-size: 0.85rem; color: var(--muted); margin-bottom: 1rem;">
              Target credentials for testing e-commerce BOLA, BFLA, and PII exposure:
            </p>
            <div class="cred-item">
              <span class="tag tag-user">User A</span>
              <strong>userA</strong> &nbsp;/&nbsp; <code>passA123</code>
              <div style="font-size: 0.8rem; color: #93c5fd; margin-top: 0.25rem;">Alice Anderson (Orders: 101, 102, 103)</div>
            </div>
            <div class="cred-item">
              <span class="tag tag-user">User B</span>
              <strong>userB</strong> &nbsp;/&nbsp; <code>passB123</code>
              <div style="font-size: 0.8rem; color: #93c5fd; margin-top: 0.25rem;">Bob Baker (Order: 104 - Target of BOLA exploit)</div>
            </div>
            <div class="cred-item">
              <span class="tag tag-admin">Admin</span>
              <strong>admin</strong> &nbsp;/&nbsp; <code>admin123</code>
              <div style="font-size: 0.8rem; color: #f3e8ff; margin-top: 0.25rem;">Super Administrator (User Directory Manager)</div>
            </div>

            <div style="margin-top: 1.5rem;">
              <a href="/docs" target="_blank" class="btn-link">&#x1F4D6; Swagger Interactive Docs</a>
              <a href="/openapi.json" target="_blank" class="btn-link" style="background: rgba(255,255,255,0.1); color: #fff;">&#x270E; OpenAPI Spec</a>
            </div>
          </div>

          <div class="panel">
            <h3>&#x1F4E6; Target Attack Surface</h3>
            <div class="record-row">
              <strong>Order #104:</strong> Bob Baker's order (Mechanical Keyboard &amp; Mouse)
              <div style="color: #fca5a5; font-size: 0.8rem;">BOLA Target: <code>GET /orders/104</code> (readable by userA)</div>
            </div>
            <div class="record-row">
              <strong>User Profile #2:</strong> Bob Baker's personal data
              <div style="color: #fca5a5; font-size: 0.8rem;">Data Exposure: <code>GET /users/2</code> (leaks SSN &amp; password hash)</div>
            </div>
            <div class="record-row">
              <strong>Admin Directory:</strong> Customer Database
              <div style="color: var(--muted); font-size: 0.8rem;">BFLA Flaw: <code>GET /admin/users</code> (accessible to regular users)</div>
            </div>
            <div class="record-row">
              <strong>Executive Financials:</strong> Revenue and margin reports
              <div style="color: var(--muted); font-size: 0.8rem;">Missing Auth: <code>GET /reports/summary</code> (no token required)</div>
            </div>
          </div>
        </div>
      </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


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
