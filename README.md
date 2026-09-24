# SentinelAPI

**SentinelAPI** is an automated API security scanner built for authorization and data-exposure testing. It parses OpenAPI (Swagger) specifications, authenticates across multiple test identities with distinct permission levels, and systematically probes for critical API vulnerabilities:
- **BOLA / IDOR** (Broken Object Level Authorization — OWASP API1:2023)
- **Broken Function Level Authorization** (OWASP API5:2023)
- **Excessive Data Exposure** (OWASP API3:2023)
- **Lack of Resources & Rate Limiting** (OWASP API4:2023)

---

## ⚠️ Ethics & Scope Statement

> **CRITICAL LEGAL & ETHICAL NOTICE**
> 
> SentinelAPI is designed exclusively for testing **explicitly authorized**, sandboxed, or owned target environments. 
> 
> - **Only scan systems you own or have explicit written authorization to test.**
> - The scanner strictly enforces an in-memory allowlist (`ALLOWED_HOSTS`) and rejects external, look-alike, or credential-bearing URLs.
> - Never disable scope boundaries against live, third-party, or production environments without permission.
> - Unauthorized scanning of remote services may violate computer fraud and cybersecurity laws.

---

## Architecture & Tech Stack

- **Backend**: Python 3.11, FastAPI, Pydantic v2, pydantic-settings, HTTPX, Prance, OpenAPI Spec Validator
- **Testing**: Pytest, pytest-asyncio
- **Orchestration**: Docker Compose (`scanner` on port 8000, sandboxed `target_api` on port 9000)
- **Frontend** (Upcoming phases): React + Vite + Tailwind CSS + Recharts

---

## Quickstart

### 1. Environment Configuration

Copy the example environment template:
```bash
cp .env.example .env
```

### 2. Run with Docker Compose

Start both the scanner and sandboxed demo target API:
```bash
docker compose up --build -d
```

Verify service health:
```bash
curl http://localhost:8000/health
curl http://localhost:9000/health
```

Check active scan scope:
```bash
curl http://localhost:8000/scope
```

To stop containers:
```bash
docker compose down
```

---

## Local Development & Testing

### 1. Set Up Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Run Test Suite

```bash
cd backend
pytest -v

cd ../target_api
pytest -v
```

---

## OpenAPI Attack Surface Parser (CLI)

SentinelAPI provides an automated attack surface mapper that loads OpenAPI 3.x specifications (from local files or allow-listed sandboxed URLs), dereferences internal schemas, and scores endpoints by risk exposure.

### CLI Usage

```bash
cd backend
python -m app.cli surface --spec http://localhost:9000/openapi.json
# Or against a local file:
python -m app.cli surface --spec tests/fixtures/target_openapi.json
```

### Sample Output

```text
                              SentinelAPI Attack Surface Mapping                
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━┓
┃ METHOD   ┃ PATH                      ┃  AUTH  ┃  OBJECT  ┃  PRIV  ┃ RESOURCE  ┃ SCORE ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━┩
│ PUT      │ /orders/{id}              │  YES   │   YES    │   NO   │ order     │   +65 │
│ DELETE   │ /orders/{id}              │  YES   │   YES    │   NO   │ order     │   +65 │
│ GET      │ /admin/users              │  YES   │    NO    │  YES   │ user      │   +60 │
│ GET      │ /users/{id}               │  YES   │   YES    │   NO   │ user      │   +55 │
│ GET      │ /orders/{id}              │  YES   │   YES    │   NO   │ order     │   +55 │
│ POST     │ /orders                   │  YES   │    NO    │   NO   │ order     │   +50 │
│ GET      │ /users/me                 │  YES   │    NO    │   NO   │ me        │   +15 │
│ GET      │ /orders                   │  YES   │    NO    │   NO   │ order     │   +15 │
│ GET      │ /reports/summary          │  YES   │    NO    │   NO   │ summary   │   +15 │
│ GET      │ /products/{id}            │   NO   │   YES    │   NO   │ product   │   +10 │
│ POST     │ /auth/login               │   NO   │    NO    │   NO   │ -         │   -20 │
│ GET      │ /products                 │   NO   │    NO    │   NO   │ product   │   -30 │
│ GET      │ /health                   │   NO   │    NO    │   NO   │ -         │  -130 │
│ POST     │ /_reset                   │   NO   │    NO    │   NO   │ -         │  -130 │
└──────────┴───────────────────────────┴────────┴──────────┴────────┴───────────┴───────┘

Surface Summary: Total: 14 | Auth Required: 9 | Object Level: 5 | Privileged: 1 | Public: 5
```

