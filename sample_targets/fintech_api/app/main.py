"""ApexBank Digital Core API - Sample Vulnerable FinTech Target."""

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.auth import bearer_scheme, create_access_token, get_current_user
from app.data import (
    delete_transfer,
    get_account_by_id,
    get_accounts,
    get_client_by_id,
    get_client_by_username,
    get_compliance_logs,
    get_transfer_by_id,
    get_transfers,
    get_treasury,
    reset_data,
)
from app.schemas import (
    BankAccount,
    ClientProfile,
    ComplianceLog,
    HealthResponse,
    LoginRequest,
    LoginResponse,
    ResetResponse,
    WireTransfer,
)

app = FastAPI(
    title="ApexBank Digital Banking & Payments API",
    description=(
        "Next-generation retail & commercial neobank core banking platform. "
        "Contains realistic banking records for security testing and live evaluation."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index() -> HTMLResponse:
    """Live web interface for the ApexBank Portal."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>ApexBank Digital Core - Banking & Payments</title>
      <style>
        :root {
          --primary: #10b981;
          --bg: #064e3b;
          --card: #065f46;
          --text: #ecfdf5;
          --muted: #a7f3d0;
          --accent: #34d399;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: #022c22; color: var(--text); min-height: 100vh; padding: 2rem 1rem; }
        .container { max-width: 1100px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 2rem; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .brand { display: flex; align-items: center; gap: 0.75rem; }
        .logo-icon { width: 40px; height: 40px; background: var(--accent); border-radius: 8px; display: grid; place-items: center; font-weight: bold; font-size: 1.5rem; color: #022c22; }
        .badge-live { background: rgba(52, 211, 153, 0.2); color: #6ee7b7; border: 1px solid #10b981; padding: 0.35rem 0.75rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.25rem; margin: 2rem 0; }
        .stat-card { background: var(--card); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 1.5rem; }
        .stat-val { font-size: 2rem; font-weight: 800; color: #6ee7b7; margin-top: 0.5rem; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-top: 2rem; }
        @media(max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
        .panel { background: var(--card); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 1.5rem; }
        .panel h3 { font-size: 1.25rem; margin-bottom: 1rem; color: var(--muted); border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 0.5rem; }
        .cred-item { background: rgba(0,0,0,0.25); padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 0.75rem; font-family: monospace; font-size: 0.9rem; }
        .tag { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; margin-right: 0.5rem; }
        .tag-client { background: #065f46; color: #a7f3d0; border: 1px solid #10b981; }
        .tag-compliance { background: #7f1d1d; color: #fecaca; }
        .btn-link { display: inline-block; background: var(--accent); color: #022c22; font-weight: 600; padding: 0.6rem 1.2rem; border-radius: 6px; text-decoration: none; margin-top: 1rem; margin-right: 0.5rem; transition: all 0.2s; }
        .btn-link:hover { background: #6ee7b7; transform: translateY(-1px); }
        .record-row { border-bottom: 1px solid rgba(255,255,255,0.06); padding: 0.75rem 0; font-size: 0.9rem; }
        .record-row:last-child { border-bottom: none; }
      </style>
    </head>
    <body>
      <div class="container">
        <header class="header">
          <div class="brand">
            <div class="logo-icon">&#x20AC;</div>
            <div>
              <h1 style="font-size: 1.5rem; font-weight: 700;">ApexBank Digital Core</h1>
              <p style="font-size: 0.85rem; color: var(--muted);">Cloud-Native Treasury, Commercial & Retail Banking</p>
            </div>
          </div>
          <div>
            <span class="badge-live">&#x25CF; Port 9002 Active</span>
          </div>
        </header>

        <section class="stats">
          <div class="stat-card">
            <div>Liquid Reserve</div>
            <div class="stat-val">$48.2M</div>
          </div>
          <div class="stat-card">
            <div>Managed Accounts</div>
            <div class="stat-val">45,900</div>
          </div>
          <div class="stat-card">
            <div>Wire Clearance</div>
            <div class="stat-val">Sub-second</div>
          </div>
          <div class="stat-card">
            <div>API Status</div>
            <div class="stat-val" style="font-size: 1.4rem; color: #34d399;">Operational</div>
          </div>
        </section>

        <div class="grid-2">
          <div class="panel">
            <h3>&#x1F511; Demo Test Credentials</h3>
            <p style="font-size: 0.85rem; color: var(--muted); margin-bottom: 1rem;">
              Target credentials for testing FinTech BOLA and AML authorization controls:
            </p>
            <div class="cred-item">
              <span class="tag tag-client">User A</span>
              <strong>clientA</strong> &nbsp;/&nbsp; <code>passA123</code>
              <div style="font-size: 0.8rem; color: #a7f3d0; margin-top: 0.25rem;">Arthur Pendelton (Checking Account ID: 301, Balance $24.5k)</div>
            </div>
            <div class="cred-item">
              <span class="tag tag-client">User B</span>
              <strong>clientB</strong> &nbsp;/&nbsp; <code>passB123</code>
              <div style="font-size: 0.8rem; color: #a7f3d0; margin-top: 0.25rem;">Beatrice Sterling (Treasury Account ID: 302, Balance $184.2k)</div>
            </div>
            <div class="cred-item">
              <span class="tag tag-compliance">Admin</span>
              <strong>auditor</strong> &nbsp;/&nbsp; <code>audit123</code>
              <div style="font-size: 0.8rem; color: #fecaca; margin-top: 0.25rem;">Chief Financial Crime & AML Compliance Officer</div>
            </div>

            <div style="margin-top: 1.5rem;">
              <a href="/docs" target="_blank" class="btn-link">&#x1F4D6; Swagger Interactive Docs</a>
              <a href="/openapi.json" target="_blank" class="btn-link" style="background: rgba(255,255,255,0.1); color: #fff;">&#x270E; OpenAPI Spec</a>
            </div>
          </div>

          <div class="panel">
            <h3>&#x1F4B0; Ledger & Wire Records</h3>
            <div class="record-row">
              <strong>Account #301:</strong> Operating Checking (Arthur Pendelton)
              <div style="color: var(--muted); font-size: 0.8rem;">Balance: $24,500.50 USD &bull; Routing: 121000358</div>
            </div>
            <div class="record-row">
              <strong>Account #302:</strong> High-Yield Treasury Vault (Beatrice Sterling)
              <div style="color: #fca5a5; font-size: 0.8rem;">Target of BOLA exploit: balance $184,250.00 &amp; full card CVV hash</div>
            </div>
            <div class="record-row">
              <strong>Transfer #702:</strong> Pending Outbound Wire $75,000 USD
              <div style="color: var(--muted); font-size: 0.8rem;">BOLA Deletion Target: <code>DELETE /transfers/702</code></div>
            </div>
            <div class="record-row">
              <strong>AML Surveillance:</strong> Suspicious Activity Log (SAR)
              <div style="color: var(--muted); font-size: 0.8rem;">Privileged Route: <code>/admin/compliance-logs</code> (BFLA flaw)</div>
            </div>
          </div>
        </div>
      </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.get("/health", response_model=HealthResponse, tags=["System"])
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="ApexBank Digital API")


@app.post("/_reset", response_model=ResetResponse, tags=["System"])
def reset_state() -> ResetResponse:
    reset_data()
    return ResetResponse(status="reset")


@app.post(
    "/auth/login",
    response_model=LoginResponse,
    summary="Client / Staff Authentication",
    description="Authenticates digital banking clients. (Missing rate limiting)",
    tags=["Authentication"],
)
def login(creds: LoginRequest) -> LoginResponse:
    client = get_client_by_username(creds.username)
    if not client or client["password"] != creds.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid banking credentials",
        )
    token = create_access_token(client["id"], client["username"], client["role"])
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user_id=client["id"],
        role=client["role"],
    )


@app.get(
    "/accounts/me",
    response_model=ClientProfile,
    summary="Current Client Profile",
    description="Returns authenticated client profile.",
    tags=["Accounts"],
    dependencies=[Depends(bearer_scheme)],
)
def get_me(current_user: dict = Depends(get_current_user)) -> ClientProfile:
    return ClientProfile(**current_user)


@app.get(
    "/accounts",
    response_model=list[BankAccount],
    summary="List Client Bank Accounts",
    description="Returns accounts owned by the authenticated caller.",
    tags=["Accounts"],
    dependencies=[Depends(bearer_scheme)],
)
def list_accounts(current_user: dict = Depends(get_current_user)) -> list[BankAccount]:
    all_acts = get_accounts()
    cid = current_user["id"]
    matching = [a for a in all_acts if a["client_id"] == cid]
    return [BankAccount(**a) for a in matching]


@app.get(
    "/accounts/{id}",
    response_model=BankAccount,
    summary="Bank Account Details & Balance",
    description="Retrieves balance, routing, and card info. Flaw: BOLA (API1:2023) - does not verify client ownership!",
    tags=["Accounts"],
    dependencies=[Depends(bearer_scheme)],
)
def get_account(id: int, current_user: dict = Depends(get_current_user)) -> BankAccount:
    act = get_account_by_id(id)
    if not act:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    # BOLA Vulnerability: Any client can access another client's bank account balance and CVV hash
    return BankAccount(**act)


@app.get(
    "/transfers",
    response_model=list[WireTransfer],
    summary="List Wire Transfers",
    description="Returns transfer transactions initiated by authenticated client.",
    tags=["Transfers"],
    dependencies=[Depends(bearer_scheme)],
)
def list_transfers(current_user: dict = Depends(get_current_user)) -> list[WireTransfer]:
    all_tx = get_transfers()
    cid = current_user["id"]
    matching = [t for t in all_tx if t["client_id"] == cid]
    return [WireTransfer(**t) for t in matching]


@app.delete(
    "/transfers/{id}",
    summary="Cancel / Delete Wire Transfer",
    description="Cancels pending wire transfer. Flaw: BOLA Write (API1:2023) - does not verify owner!",
    tags=["Transfers"],
    dependencies=[Depends(bearer_scheme)],
    status_code=status.HTTP_204_NO_CONTENT,
)
def cancel_transfer(id: int, current_user: dict = Depends(get_current_user)) -> None:
    tx = get_transfer_by_id(id)
    if not tx:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transfer not found")
    # BOLA Write Vulnerability: Any client can delete/cancel transfers belonging to other clients
    delete_transfer(id)
    return None


@app.get(
    "/admin/compliance-logs",
    response_model=list[ComplianceLog],
    summary="AML Surveillance & SAR Audit Logs (Privileged)",
    description="Lists anti-money laundering investigations. Flaw: BFLA (API5:2023) - accessible to standard clients!",
    tags=["admin"],
    dependencies=[Depends(bearer_scheme)],
)
def list_compliance_logs(current_user: dict = Depends(get_current_user)) -> list[ComplianceLog]:
    # BFLA Vulnerability: Does not verify current_user["role"] == "admin"!
    logs = get_compliance_logs()
    return [ComplianceLog(**l) for l in logs]


@app.get(
    "/treasury/liquidity",
    summary="Core Bank Treasury Liquidity Metrics",
    description="Capital ratios and liquidity reserve numbers.",
    tags=["Treasury"],
    dependencies=[Depends(bearer_scheme)],
)
def get_treasury_metrics() -> dict:
    # Broken Authentication Vulnerability: Route declares security scheme in OpenAPI, but endpoint allows unauthenticated requests
    return get_treasury()
