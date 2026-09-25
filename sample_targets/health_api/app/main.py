"""MedPulse Health Portal API - Sample Vulnerable Healthcare Target."""

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.auth import bearer_scheme, create_access_token, get_current_user
from app.data import (
    get_patient_by_id,
    get_patient_by_username,
    get_patients,
    get_prescriptions,
    get_record_by_id,
    get_records,
    get_trials,
    reset_data,
)
from app.schemas import (
    HealthResponse,
    LoginRequest,
    LoginResponse,
    MedicalRecord,
    PatientProfile,
    PrescriptionRecord,
    ResetResponse,
    UpdateRecordRequest,
)

app = FastAPI(
    title="MedPulse Health & Clinical Records API",
    description=(
        "Hospital EHR and Patient Portal API containing realistic healthcare data. "
        "Intended for authorized security scanning and demonstration with SentinelAPI."
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
    """Live web interface for the MedPulse Clinical Portal."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>MedPulse Healthcare - Clinical Records Network</title>
      <style>
        :root {
          --primary: #0d9488;
          --primary-dark: #0f766e;
          --bg: #042f2e;
          --surface: #115e59;
          --card: #134e4a;
          --text: #f0fdfa;
          --muted: #99f6e4;
          --accent: #14b8a6;
          --danger: #f43f5e;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: #031a19; color: var(--text); min-height: 100vh; padding: 2rem 1rem; }
        .container { max-width: 1100px; margin: 0 auto; }
        .header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 2rem; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .brand { display: flex; align-items: center; gap: 0.75rem; }
        .logo-icon { width: 40px; height: 40px; background: var(--accent); border-radius: 8px; display: grid; place-items: center; font-weight: bold; font-size: 1.5rem; color: #042f2e; }
        .badge-live { background: rgba(20, 184, 166, 0.2); color: #5eead4; border: 1px solid #14b8a6; padding: 0.35rem 0.75rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.25rem; margin: 2rem 0; }
        .stat-card { background: var(--card); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 1.5rem; }
        .stat-val { font-size: 2rem; font-weight: 800; color: #5eead4; margin-top: 0.5rem; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-top: 2rem; }
        @media(max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
        .panel { background: var(--card); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 1.5rem; }
        .panel h3 { font-size: 1.25rem; margin-bottom: 1rem; color: var(--muted); border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 0.5rem; }
        .cred-item { background: rgba(0,0,0,0.25); padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 0.75rem; font-family: monospace; font-size: 0.9rem; }
        .tag { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; margin-right: 0.5rem; }
        .tag-patient { background: #0e7490; color: #cffafe; }
        .tag-doctor { background: #7c2d12; color: #ffedd5; }
        .btn-link { display: inline-block; background: var(--accent); color: #042f2e; font-weight: 600; padding: 0.6rem 1.2rem; border-radius: 6px; text-decoration: none; margin-top: 1rem; margin-right: 0.5rem; transition: all 0.2s; }
        .btn-link:hover { background: #5eead4; transform: translateY(-1px); }
        .record-row { border-bottom: 1px solid rgba(255,255,255,0.06); padding: 0.75rem 0; font-size: 0.9rem; }
        .record-row:last-child { border-bottom: none; }
      </style>
    </head>
    <body>
      <div class="container">
        <header class="header">
          <div class="brand">
            <div class="logo-icon">&#x2695;</div>
            <div>
              <h1 style="font-size: 1.5rem; font-weight: 700;">MedPulse Health Portal</h1>
              <p style="font-size: 0.85rem; color: var(--muted);">Regional Hospital EHR & Clinical Trial Network</p>
            </div>
          </div>
          <div>
            <span class="badge-live">&#x25CF; Port 9001 Active</span>
          </div>
        </header>

        <section class="stats">
          <div class="stat-card">
            <div>Registered Patients</div>
            <div class="stat-val">12,480</div>
          </div>
          <div class="stat-card">
            <div>Clinical Records</div>
            <div class="stat-val">34,120</div>
          </div>
          <div class="stat-card">
            <div>Active Trials</div>
            <div class="stat-val">18 Sites</div>
          </div>
          <div class="stat-card">
            <div>API Status</div>
            <div class="stat-val" style="font-size: 1.4rem; color: #34d399;">Online</div>
          </div>
        </section>

        <div class="grid-2">
          <div class="panel">
            <h3>&#x1F511; Demo Test Credentials</h3>
            <p style="font-size: 0.85rem; color: var(--muted); margin-bottom: 1rem;">
              Use these persona accounts in SentinelAPI to scan and analyze healthcare authorization flaws:
            </p>
            <div class="cred-item">
              <span class="tag tag-patient">User A</span>
              <strong>patientA</strong> &nbsp;/&nbsp; <code>passA123</code>
              <div style="font-size: 0.8rem; color: #99f6e4; margin-top: 0.25rem;">Patient Eleanor Vance (Record ID: 201)</div>
            </div>
            <div class="cred-item">
              <span class="tag tag-patient">User B</span>
              <strong>patientB</strong> &nbsp;/&nbsp; <code>passB123</code>
              <div style="font-size: 0.8rem; color: #99f6e4; margin-top: 0.25rem;">Patient Marcus Thorne (Record ID: 202 - Sensitive Cardiac Chart)</div>
            </div>
            <div class="cred-item">
              <span class="tag tag-doctor">Admin</span>
              <strong>dr_smith</strong> &nbsp;/&nbsp; <code>doctor123</code>
              <div style="font-size: 0.8rem; color: #fed7aa; margin-top: 0.25rem;">Chief Attending Physician (Prescription Admin)</div>
            </div>

            <div style="margin-top: 1.5rem;">
              <a href="/docs" target="_blank" class="btn-link">&#x1F4D6; Swagger Interactive Docs</a>
              <a href="/openapi.json" target="_blank" class="btn-link" style="background: rgba(255,255,255,0.1); color: #fff;">&#x270E; OpenAPI Spec</a>
            </div>
          </div>

          <div class="panel">
            <h3>&#x1F4CB; Live Clinical Record Index</h3>
            <div class="record-row">
              <strong>Record #201:</strong> Cardiovascular Health & Baseline Vitals (Eleanor Vance)
              <div style="color: var(--muted); font-size: 0.8rem;">Diagnosis: Sinus Bradycardia (Stable)</div>
            </div>
            <div class="record-row">
              <strong>Record #202:</strong> Critical Cardiac Ablation & Arrhythmia Protocol (Marcus Thorne)
              <div style="color: #fca5a5; font-size: 0.8rem;">Protected Clinical Data (BOLA vulnerability probe target)</div>
            </div>
            <div class="record-row">
              <strong>Controlled Rx:</strong> Prescription Audit Directory (Oxycodone, Atorvastatin)
              <div style="color: var(--muted); font-size: 0.8rem;">Privileged Route: <code>/admin/prescriptions</code> (BFLA target)</div>
            </div>
            <div class="record-row">
              <strong>Trial Data:</strong> Global Beta-Blocker Efficacy Study
              <div style="color: var(--muted); font-size: 0.8rem;">Public trial unauthenticated route: <code>/clinical/trials</code></div>
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
    return HealthResponse(status="ok", service="MedPulse Health Portal")


@app.post("/_reset", response_model=ResetResponse, tags=["System"])
def reset_state() -> ResetResponse:
    reset_data()
    return ResetResponse(status="reset")


@app.post(
    "/auth/login",
    response_model=LoginResponse,
    summary="Patient / Staff Authentication",
    description="Authenticates patients or staff. (Missing rate limiting)",
    tags=["Authentication"],
)
def login(creds: LoginRequest) -> LoginResponse:
    patient = get_patient_by_username(creds.username)
    if not patient or patient["password"] != creds.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    token = create_access_token(patient["id"], patient["username"], patient["role"])
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user_id=patient["id"],
        role=patient["role"],
    )


@app.get(
    "/patients/me",
    response_model=PatientProfile,
    summary="Current Patient Profile",
    description="Returns authenticated patient profile.",
    tags=["Patients"],
    dependencies=[Depends(bearer_scheme)],
)
def get_me(current_user: dict = Depends(get_current_user)) -> PatientProfile:
    return PatientProfile(**current_user)


@app.get(
    "/patients/{id}",
    response_model=PatientProfile,
    summary="Patient Record by ID",
    description="Fetches demographic patient record. Leaks SSN and medical record number (Excessive Data Exposure / PII).",
    tags=["Patients"],
    dependencies=[Depends(bearer_scheme)],
)
def get_patient(id: int, current_user: dict = Depends(get_current_user)) -> PatientProfile:
    patient = get_patient_by_id(id)
    if not patient:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")
    # Vulnerability: Leaks full patient profile with SSN and emergency contacts to any authenticated caller
    return PatientProfile(**patient)


@app.get(
    "/records",
    response_model=list[MedicalRecord],
    summary="List Patient Medical Records",
    description="Collection endpoint listing medical records belonging to current patient.",
    tags=["Medical Records"],
    dependencies=[Depends(bearer_scheme)],
)
def list_records(current_user: dict = Depends(get_current_user)) -> list[MedicalRecord]:
    # Returns records for current authenticated patient
    all_recs = get_records()
    user_id = current_user["id"]
    matching = [r for r in all_recs if r["patient_id"] == user_id]
    return [MedicalRecord(**r) for r in matching]


@app.get(
    "/records/{id}",
    response_model=MedicalRecord,
    summary="Medical Record Chart Details",
    description="Fetches specific clinical chart. Flaw: BOLA (API1:2023) - does not verify patient ownership!",
    tags=["Medical Records"],
    dependencies=[Depends(bearer_scheme)],
)
def get_record(id: int, current_user: dict = Depends(get_current_user)) -> MedicalRecord:
    rec = get_record_by_id(id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Clinical record not found")
    # BOLA Vulnerability: Any patient can view any other patient's clinical diagnosis and lab charts!
    return MedicalRecord(**rec)


@app.put(
    "/records/{id}",
    response_model=MedicalRecord,
    summary="Update Clinical Record Notes",
    description="Modifies clinical record notes. Flaw: BOLA Write (API1:2023) - does not verify patient ownership!",
    tags=["Medical Records"],
    dependencies=[Depends(bearer_scheme)],
)
def update_record(id: int, body: UpdateRecordRequest, current_user: dict = Depends(get_current_user)) -> MedicalRecord:
    rec = get_record_by_id(id)
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Clinical record not found")
    # BOLA Write Vulnerability
    if body.notes is not None:
        rec["notes"] = body.notes
    if body.diagnosis is not None:
        rec["diagnosis"] = body.diagnosis
    return MedicalRecord(**rec)


@app.get(
    "/admin/prescriptions",
    response_model=list[PrescriptionRecord],
    summary="Hospital Prescription Registry (Privileged)",
    description="List controlled substance prescriptions. Flaw: BFLA (API5:2023) - accessible to regular patients!",
    tags=["admin"],
    dependencies=[Depends(bearer_scheme)],
)
def list_prescriptions(current_user: dict = Depends(get_current_user)) -> list[PrescriptionRecord]:
    # BFLA Vulnerability: Does not verify current_user["role"] == "admin"!
    all_rx = get_prescriptions()
    return [PrescriptionRecord(**rx) for rx in all_rx]


@app.get(
    "/clinical/trials",
    summary="Clinical Trial Interim Data",
    description="Access clinical trials and unblinded patient efficacy results.",
    tags=["Clinical"],
    dependencies=[Depends(bearer_scheme)],
)
def list_trials() -> list[dict]:
    # Broken Authentication Vulnerability: Route declares security scheme in OpenAPI, but endpoint allows unauthenticated requests
    return get_trials()
