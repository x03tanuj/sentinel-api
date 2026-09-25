"""Aegis Cloud Zero-Trust Workspace API - Fully Hardened Sample Target."""

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.auth import bearer_scheme, create_access_token, get_current_user, require_admin
from app.data import (
    check_rate_limit,
    delete_document,
    get_audit_logs,
    get_document_by_id,
    get_documents,
    get_user_by_id,
    get_user_by_username,
    reset_data,
)
from app.schemas import (
    AuditLogResponse,
    DocumentResponse,
    HealthResponse,
    LoginRequest,
    LoginResponse,
    ResetResponse,
    UpdateDocumentRequest,
    UserProfileMe,
    UserProfilePublic,
)

app = FastAPI(
    title="Aegis Cloud Workspace API (Hardened / Zero-Trust)",
    description=(
        "Enterprise cloud document collaboration platform enforcing strict zero-trust "
        "object-level authorization, role-based access control, rate limiting, and data minimization."
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
    """Live web interface for the Aegis Zero-Trust Portal."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Aegis Cloud - Enterprise Zero-Trust Workspace</title>
      <style>
        :root {
          --primary: #6366f1;
          --bg: #1e1b4b;
          --card: #312e81;
          --text: #e0e7ff;
          --muted: #a5b4fc;
          --accent: #818cf8;
          --shield: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: #0f0e2a; color: var(--text); min-height: 100vh; padding: 2rem 1rem; }
        .container { max-width: 1100px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 2rem; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .brand { display: flex; align-items: center; gap: 0.75rem; }
        .logo-icon { width: 40px; height: 40px; background: var(--shield); border-radius: 8px; display: grid; place-items: center; font-weight: bold; font-size: 1.5rem; color: #064e3b; }
        .badge-live { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; padding: 0.35rem 0.75rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.25rem; margin: 2rem 0; }
        .stat-card { background: var(--card); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 1.5rem; }
        .stat-val { font-size: 1.8rem; font-weight: 800; color: #c7d2fe; margin-top: 0.5rem; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-top: 2rem; }
        @media(max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
        .panel { background: var(--card); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 1.5rem; }
        .panel h3 { font-size: 1.25rem; margin-bottom: 1rem; color: var(--muted); border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 0.5rem; }
        .cred-item { background: rgba(0,0,0,0.25); padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 0.75rem; font-family: monospace; font-size: 0.9rem; }
        .tag { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; margin-right: 0.5rem; }
        .tag-user { background: #3730a3; color: #e0e7ff; border: 1px solid #6366f1; }
        .tag-admin { background: #064e3b; color: #a7f3d0; border: 1px solid #10b981; }
        .btn-link { display: inline-block; background: var(--shield); color: #022c22; font-weight: 600; padding: 0.6rem 1.2rem; border-radius: 6px; text-decoration: none; margin-top: 1rem; margin-right: 0.5rem; transition: all 0.2s; }
        .btn-link:hover { background: #34d399; transform: translateY(-1px); }
        .record-row { border-bottom: 1px solid rgba(255,255,255,0.06); padding: 0.75rem 0; font-size: 0.9rem; }
        .record-row:last-child { border-bottom: none; }
        .shield-badge { display: inline-flex; align-items: center; gap: 0.35rem; color: #34d399; font-size: 0.85rem; font-weight: 600; }
      </style>
    </head>
    <body>
      <div class="container">
        <header class="header">
          <div class="brand">
            <div class="logo-icon">&#x1F6E1;</div>
            <div>
              <h1 style="font-size: 1.5rem; font-weight: 700;">Aegis Cloud Zero-Trust Workspace</h1>
              <p style="font-size: 0.85rem; color: var(--muted);">Encrypted Documents &amp; Fine-Grained Authorization</p>
            </div>
          </div>
          <div>
            <span class="badge-live">&#x25CF; Port 9003 Active</span>
          </div>
        </header>

        <section class="stats">
          <div class="stat-card">
            <div>Security Posture</div>
            <div class="stat-val" style="color: #34d399;">100% Hardened</div>
          </div>
          <div class="stat-card">
            <div>Compliance Tier</div>
            <div class="stat-val">SOC 2 Type II</div>
          </div>
          <div class="stat-card">
            <div>Rate Limiter</div>
            <div class="stat-val" style="color: #34d399;">Enforced</div>
          </div>
          <div class="stat-card">
            <div>Expected Findings</div>
            <div class="stat-val" style="color: #34d399;">0 (Clean PASS)</div>
          </div>
        </section>

        <div class="grid-2">
          <div class="panel">
            <h3>&#x1F511; Demo Test Credentials</h3>
            <p style="font-size: 0.85rem; color: var(--muted); margin-bottom: 1rem;">
              Scan this target to verify that SentinelAPI validates secure barriers and reports 0 findings:
            </p>
            <div class="cred-item">
              <span class="tag tag-user">User A</span>
              <strong>userA</strong> &nbsp;/&nbsp; <code>passA123</code>
              <div style="font-size: 0.8rem; color: #a5b4fc; margin-top: 0.25rem;">Alexander Hayes (DevOps - Document ID: 401)</div>
            </div>
            <div class="cred-item">
              <span class="tag tag-user">User B</span>
              <strong>userB</strong> &nbsp;/&nbsp; <code>passB123</code>
              <div style="font-size: 0.8rem; color: #a5b4fc; margin-top: 0.25rem;">Brianna Chen (Product - Document ID: 402)</div>
            </div>
            <div class="cred-item">
              <span class="tag tag-admin">Admin</span>
              <strong>secadmin</strong> &nbsp;/&nbsp; <code>admin123</code>
              <div style="font-size: 0.8rem; color: #a7f3d0; margin-top: 0.25rem;">SecOps Global Information Security Administrator</div>
            </div>

            <div style="margin-top: 1.5rem;">
              <a href="/docs" target="_blank" class="btn-link">&#x1F4D6; Swagger Interactive Docs</a>
              <a href="/openapi.json" target="_blank" class="btn-link" style="background: rgba(255,255,255,0.1); color: #fff;">&#x270E; OpenAPI Spec</a>
            </div>
          </div>

          <div class="panel">
            <h3>&#x1F6E1; Enforced Defenses</h3>
            <div class="record-row">
              <span class="shield-badge">&#x2714; Strict BOLA Defense:</span>
              <div style="color: var(--muted); font-size: 0.8rem;">Accessing another user's document ID returns <code>403 Forbidden</code>.</div>
            </div>
            <div class="record-row">
              <span class="shield-badge">&#x2714; Strict BFLA Defense:</span>
              <div style="color: var(--muted); font-size: 0.8rem;">Accessing <code>/admin/audit-logs</code> without admin role returns <code>403 Forbidden</code>.</div>
            </div>
            <div class="record-row">
              <span class="shield-badge">&#x2714; Rate Limiting Defense:</span>
              <div style="color: var(--muted); font-size: 0.8rem;">Bursts on <code>/auth/login</code> return <code>429 Too Many Requests</code> with <code>Retry-After</code>.</div>
            </div>
            <div class="record-row">
              <span class="shield-badge">&#x2714; Data Minimization:</span>
              <div style="color: var(--muted); font-size: 0.8rem;"><code>/users/{id}</code> exposes only public name and department; no SSN or secrets.</div>
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
    return HealthResponse(status="ok", service="Aegis Workspace", compliance="SOC2-TypeII")


@app.post("/_reset", response_model=ResetResponse, tags=["System"])
def reset_state() -> ResetResponse:
    reset_data()
    return ResetResponse(status="reset")


@app.post(
    "/auth/login",
    response_model=LoginResponse,
    summary="Enterprise Single Sign-On / Login",
    description="Authenticates enterprise accounts with strict rate limiting.",
    tags=["Authentication"],
)
def login(creds: LoginRequest, request: Request, response: Response) -> LoginResponse:
    client_ip = request.client.host if request.client else "default"
    # Rate limit: max 15 requests per 60 seconds
    if not check_rate_limit(client_ip, max_requests=15, window_seconds=60.0):
        response.headers["Retry-After"] = "30"
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait 30 seconds before retrying.",
            headers={"Retry-After": "30"},
        )

    user = get_user_by_username(creds.username)
    if not user or user["password"] != creds.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    token = create_access_token(user["id"], user["username"], user["role"])
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user_id=user["id"],
        role=user["role"],
    )


@app.get(
    "/users/me",
    response_model=UserProfileMe,
    summary="Current User Profile",
    description="Returns current authenticated user details.",
    tags=["Users"],
    dependencies=[Depends(bearer_scheme)],
)
def get_me(current_user: dict = Depends(get_current_user)) -> UserProfileMe:
    return UserProfileMe(**current_user)


@app.get(
    "/users/{id}",
    response_model=UserProfilePublic,
    summary="Public User Directory",
    description="Returns sanitized public profile. Validates user ownership.",
    tags=["Users"],
    dependencies=[Depends(bearer_scheme)],
)
def get_user(id: int, current_user: dict = Depends(get_current_user)) -> UserProfilePublic:
    u = get_user_by_id(id)
    if not u:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if u["id"] != current_user["id"] and current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot view profile of other users",
        )
    # Data minimization strictly enforced: only public fields returned
    return UserProfilePublic(id=u["id"], full_name=u["full_name"], department=u["department"])


@app.get(
    "/documents",
    response_model=list[DocumentResponse],
    summary="List Owned Documents",
    description="Returns documents owned by the caller.",
    tags=["Documents"],
    dependencies=[Depends(bearer_scheme)],
)
def list_documents(current_user: dict = Depends(get_current_user)) -> list[DocumentResponse]:
    all_docs = get_documents()
    uid = current_user["id"]
    matching = [d for d in all_docs if d["user_id"] == uid]
    return [DocumentResponse(**d) for d in matching]


@app.get(
    "/documents/{id}",
    response_model=DocumentResponse,
    summary="Document Details by ID",
    description="Fetches document details. Strictly enforces object-level authorization (BOLA defense).",
    tags=["Documents"],
    dependencies=[Depends(bearer_scheme)],
)
def get_document(id: int, current_user: dict = Depends(get_current_user)) -> DocumentResponse:
    doc = get_document_by_id(id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    # Strict BOLA check: Only document owner or admin can read
    if doc["user_id"] != current_user["id"] and current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have permission to access this document",
        )
    return DocumentResponse(**doc)


@app.put(
    "/documents/{id}",
    response_model=DocumentResponse,
    summary="Update Document Content",
    description="Modifies document. Strictly enforces ownership (BOLA Write defense).",
    tags=["Documents"],
    dependencies=[Depends(bearer_scheme)],
)
def update_document(id: int, body: UpdateDocumentRequest, current_user: dict = Depends(get_current_user)) -> DocumentResponse:
    doc = get_document_by_id(id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    # Strict BOLA check: Only document owner can edit
    if doc["user_id"] != current_user["id"] and current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have permission to modify this document",
        )
    if body.title is not None:
        doc["title"] = body.title
    if body.content is not None:
        doc["content"] = body.content
    return DocumentResponse(**doc)


@app.delete(
    "/documents/{id}",
    summary="Delete Document",
    description="Deletes document. Strictly enforces ownership (BOLA Write defense).",
    tags=["Documents"],
    dependencies=[Depends(bearer_scheme)],
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_doc(id: int, current_user: dict = Depends(get_current_user)) -> None:
    doc = get_document_by_id(id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    # Strict BOLA check: Only document owner can delete
    if doc["user_id"] != current_user["id"] and current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have permission to delete this document",
        )
    delete_document(id)
    return None


@app.get(
    "/admin/audit-logs",
    response_model=list[AuditLogResponse],
    summary="Security Audit Logs (Privileged)",
    description="Privileged audit trails. Strictly enforces role == 'admin' (BFLA defense).",
    tags=["admin"],
    dependencies=[Depends(bearer_scheme)],
)
def list_audit_logs(admin_user: dict = Depends(require_admin)) -> list[AuditLogResponse]:
    # Strictly gated to role == 'admin'
    return [AuditLogResponse(**log) for log in get_audit_logs()]


@app.get(
    "/system/metrics",
    summary="System Operational Telemetry",
    description="Telemetry metrics. Requires valid bearer token.",
    tags=["System"],
    dependencies=[Depends(bearer_scheme)],
)
def get_system_metrics(current_user: dict = Depends(get_current_user)) -> dict:
    # Requires authentication
    return {
        "uptime_percent": 99.99,
        "active_sessions": 412,
        "encryption": "AES-256-GCM / TLS 1.3",
        "zero_trust_status": "ENFORCED",
    }
