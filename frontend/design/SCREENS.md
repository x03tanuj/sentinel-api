# SentinelAPI Screen-to-API Architecture & Forensics Specification

## Technical Investigation: Real Finding Evidence Structure (Task 0 Finding)
Before designing the differential inspector and screen interactions, the backend engine evidence models and serialization routines (`backend/app/engine/evidence.py`, `backend/app/engine/redaction.py`, `backend/app/engine/differential.py`, and `backend/tests/test_evidence.py`) were inspected to confirm the exact payload shapes:

> **Finding:** Stored `baseline_response` and `attack_response` in `Evidence` contain **complete JSON response bodies** (with credentials such as passwords, auth tokens, and SSNs sanitized via `redact_response` to `'***REDACTED***'`).
>
> In addition, `evidence.response_diff` provides:
> 1. `masked_sensitive_values`: Specific leaked fields where the value preserves the first 2 and last 2 characters (e.g. `"44*******66"` for credit cards or SSNs).
> 2. `sensitive_fields_exposed`: Dictionary mapping sensitivity tiers (`CRITICAL`, `HIGH`, `MEDIUM`) to exposed field names.
> 3. `status_divergence`: Boolean indicating whether status codes diverged.
> 4. `reproduction`: Object containing `reproduced: bool`, `attempts: int`, `downgraded: bool`.
> 5. `risk_breakdown`: Dict containing `impact`, `exploitability`, `data_sensitivity`, `evidence_strength`.
>
> **Design Implication:** The differential visualizer in Zone 3B is designed to render side-by-side formatted JSON blocks directly from `evidence.baseline_response.body` and `evidence.attack_response.body`, with inline diff badges highlighting keys identified in `response_diff`.

---

## Screen Catalog & API Route Mappings

### Screen 01: Results Triage Workspace (`01-results-triage-workspace`)
- **Stitch Screen ID:** `99bb5373e5b44eea98dbe1674b38e53a`
- **Purpose:** Primary SecOps workstation providing instant situational awareness, tactical metric HUDs, filterable finding stream, and deep-dive differential forensics.
- **Exact API Routes (from `openapi.json`):**
  - `GET /scans/{id}`: High-level scan metadata, status, target host, and summary counts.
  - `GET /scans/{id}/findings`: Filterable findings list (supports query params: `severity`, `check`, `min_confidence`, `sort`, `order`).
  - `GET /scans/{id}/findings/{finding_id}`: Granular finding details and evidence artifact.
  - `GET /scans/{id}/report.md`: Markdown compliance audit report download.
  - `GET /scans/{id}/report.json`: Full JSON audit report download.
- **Exact Response Fields Shown:**
  - `scan.target_url`, `scan.spec_source`, `scan.status` (`READY`, `SCANNING`).
  - `summary.endpoints_audited`, `summary.critical`, `summary.high`, `summary.medium`, `summary.low`, `summary.info`.
  - Finding Cards: `id`, `method`, `path`, `title`, `severity`, `confidence`, `owasp_id`, `evidence.identity`.
  - Inspector: `title`, `severity`, `confidence`, `owasp_id`, `evidence.expected_status`, `evidence.actual_status`, `evidence.baseline_response`, `evidence.attack_response`, `evidence.response_diff`, `curl_poc`, `remediation`.
- **Interactions:**
  - Click filter pills (`All`, `Critical`, `High`, `Medium`, `Low`, `Info`, `Secure`) to filter finding list.
  - Real-time search input (`⌘K`) with filter syntax (`path:/orders`, `method:GET`).
  - Select finding card to dynamically load inspector payload into Zone 3B.
  - Click `📋 Copy cURL` button: copies reproducible cURL command with checkmark feedback.
  - Click `▶ Run Scan` button: opens New Scan dialog.
  - Click `Export` dropdown: downloads JSON report, Markdown report, or compiles cURL suite.
  - Click `[View Secure Endpoint 403 Variant]`: toggles inspector view to preview a compliant endpoint (403 expected & received).
- **Loading, Empty & Error States:**
  - Loading: Zone 2 and Zone 3 render skeleton frames (`Skeleton`).
  - Empty: When filters match zero items, displays "No findings match these filters".
  - Error: If finding fails to load, shows diagnostic callout with retry button.

---

### Inspector Deep-Dive Forensic Field Mapping Table
| UI Inspector Element | Backend Model Source | Exact Path in API Response | Formatting & Presentation |
|---|---|---|---|
| Finding Title | `Finding.title` | `finding.title` | Inter bold headline, e.g. "BOLA in Order Resource Access" |
| Method Badge | `Finding.method` | `finding.method` | Monospace chip in method color (`GET`, `PUT`, `DELETE`) |
| Endpoint Path | `Finding.path` | `finding.path` | Monospace string with `{id}` parameter token highlighted |
| Severity Badge | `Finding.severity` | `finding.severity` | `SeverityChip` with icon + label (`● CRITICAL`, `#EF4444`) |
| OWASP Identifier | `Finding.owasp_id` | `finding.owasp_id` | Monospace pill: `API1:2023` (Broken Object Level Auth) |
| Confidence Rating | `Finding.confidence` | `finding.confidence` | Percentage and decimal: `95% (0.95)` |
| Composite Risk Score | Risk Engine | `finding.evidence.response_diff.risk_score` | Circular gauge or progress meter: `88 / 100 CRITICAL RISK` |
| Risk Bar 1: Impact | Risk Engine | `finding.evidence.response_diff.risk_breakdown.impact` | Progress bar 0-40: `35 / 40` (high unauthorized data access) |
| Risk Bar 2: Exploitability | Risk Engine | `finding.evidence.response_diff.risk_breakdown.exploitability` | Progress bar 0-25: `22 / 25` (trivial standard user token) |
| Risk Bar 3: Data Sensitivity | Risk Engine | `finding.evidence.response_diff.risk_breakdown.data_sensitivity` | Progress bar 0-30: `21 / 30` (PII & order records exposed) |
| Risk Bar 4: Evidence Strength | Risk Engine | `finding.evidence.response_diff.risk_breakdown.evidence_strength` | Progress bar 0-15: `10 / 15` (reproduced live differential) |
| cURL Reproducer Code | `Finding.curl_poc` | `finding.curl_poc` | Monospace code block with `$TOKEN` substitution |
| cURL Guidance Note | Static Guidance | Static helper | `# Note: export TOKEN=<attacker token> first` |
| Left Panel (Owner Baseline) | `Evidence.baseline_response` | `finding.evidence.baseline_response.body` | Formatted JSON tree with `200 OK` status pill |
| Right Panel (Attacker Probe) | `Evidence.attack_response` | `finding.evidence.attack_response.body` | Formatted JSON tree with status divergence badge |
| Status Divergence Badge | Evidence Engine | `expected_status` vs `actual_status` | Red badge: `Expected 403, got 200 - Access Granted` |
| Leaked Fields Highlight | `DiffResult` | `finding.evidence.response_diff.masked_sensitive_values` | Highlighted diff row with masked PII: `44*******66` |
| Reproduction Status | `Evidence.response_diff` | `finding.evidence.response_diff.reproduction` | Badge: `● 2 of 2 reproduced (Live Verified)` |
| Affected Objects List | `Evidence.response_diff` | `finding.evidence.response_diff.affected_objects` | Monospace pills: `[101] [102] [103] [104]` |
| Remediation Fix Hint | `Finding.remediation` | `finding.remediation` | Callout box with one-line code patch instruction |
| AI Suggested Fix | Phase 10 | Placeholder | Collapsed drawer: `Available after AI analysis in Phase 10` |

---

### Screen 02: New Scan Configuration Dialog (`02-new-scan`)
- **Stitch Screen ID:** `8de9b5734631490ea23b282c0e5c9360`
- **Purpose:** Modal interface to configure audit scope, target URL, multiple test personas, check suites, and execution budgets.
- **Exact API Routes (from `openapi.json`):**
  - `POST /scans`: Submits validated `ScanConfig` payload (returns `202 Accepted` with `scan_id`).
- **Exact Response Fields Shown:**
  - Prefilled `spec_url`: `"http://target_api:9000/openapi.json"`.
  - Prefilled `base_url`: `"http://target_api:9000"`.
  - Test Identities: `[{"name": "userA", "role": "user", "username": "user_a"}, {"name": "userB", ...}]`.
  - Check toggles: `["bola", "bfla", "data_exposure", "rate_limit", "unauth_access", "input_handling"]`.
  - Sliders: `test_case_budget` (150), `max_requests` (300).
- **Interactions:**
  - Switch between OpenAPI Spec URL and Paste JSON tabs.
  - Add / remove identity rows (up to 5 identities).
  - Password inputs display helper note: *"Passwords are never stored on disk; enter per session."*
  - Interactive budget slider with dynamic badge updating.
  - "I am authorized to test this target" checkbox gates the Launch button.
  - Demonstrates inline validation error on empty credentials.
- **Loading, Empty & Error States:**
  - Validation error: 400 Bad Request triggers inline field error highlighting.
  - Scope Guard error: Reject unauthorized targets before dispatch.

---

### Screen 03: Live Scan Progress & Telemetry Monitor (`03-live-scan-progress`)
- **Stitch Screen ID:** `460df3d8968d4c8992732c55a204cf08`
- **Purpose:** Real-time visibility into the 8-stage scan pipeline, active test concurrency, live findings ticker, and SSE log stream.
- **Exact API Routes (from `openapi.json`):**
  - `GET /scans/{id}`: Periodic or initial scan state.
  - `GET /scans/{id}/events`: Server-Sent Events (SSE) stream (`text/event-stream`).
  - `POST /scans/{id}/cancel`: Graceful abort triggering shielded cleanup of created test fixtures.
- **Exact Response Fields Shown:**
  - `event.stage`: `LOADING_SPEC`, `MAPPING_SURFACE`, `AUTHENTICATING`, `DISCOVERING`, `PLANNING`, `RUNNING_CHECKS`, `REPRODUCING`, `FINALIZING`.
  - `event.percent`: Integer 0 - 100.
  - `event.requests_sent`, `event.request_budget`.
  - `event.elapsed_seconds`, `event.estimated_remaining_seconds`.
  - `event.live_findings_count`: Severity breakdown.
  - Monospace log messages streamed over SSE.
- **Interactions:**
  - Cancel button opens confirmation modal: *"Graceful abort: in-flight probes finish and created objects are cleaned up."*
  - Autoscroll toggle: freezes terminal log for inspection or auto-tails live probes.
  - Click on detected finding opens preview drawer.

---

### Screen 04: Ground-Truth Authorization Matrix (`04-authorization-matrix`)
- **Stitch Screen ID:** `9c75f882ee564374bba85d0ef1ce91ae`
- **Purpose:** Cross-identity visualization displaying resource ownership vs runtime access boundaries across all test personas.
- **Exact API Routes (from `openapi.json`):**
  - `GET /scans/{id}/matrix`: Retrieves ground-truth matrix cells and summary statistics.
- **Exact Response Fields Shown:**
  - `cells`: Array of `{resource, object_id, owner, identity, expected_outcome, actual_status, outcome_status, finding_id}`.
  - Summary metrics: `total_cells` (28), `expected_denials` (14), `authorized_access` (11), `violations` (3).
- **Interactions:**
  - Resource filter dropdown (`All Resources`, `orders`, `users`, `reports`).
  - Click on red `VIOLATION` cell: jumps directly to the corresponding finding in the Results Triage Workspace.
  - Hover over cell: displays tooltip showing exact status code, baseline comparison, and latency.

---

### Screen 05: Discovered Attack Surface (`05-attack-surface`)
- **Stitch Screen ID:** `63431982810840d094dc996a4d89841e`
- **Purpose:** Inventory and risk-ranking table of all endpoints extracted from the OpenAPI schema.
- **Exact API Routes (from `openapi.json`):**
  - `GET /scans/{id}/surface`: List of discovered `Endpoint` models with resolved schemas and inferred properties.
- **Exact Response Fields Shown:**
  - `endpoint.method`: HTTP verb chip.
  - `endpoint.path`: Route string in monospace.
  - `endpoint.auth_required`: Boolean with lock icon.
  - `endpoint.is_object_level`: Boolean badge.
  - `endpoint.is_privileged`: Boolean badge.
  - `endpoint.resource`: Inferred resource category.
  - Priority bar: visual risk gauge (0 - 100).
- **Interactions:**
  - Column header click: sorts table by method, path, resource, or priority.
  - Method filters: toggle `GET`, `POST`, `PUT`, `DELETE`.
  - Search input: fuzzy filter by path or keyword.
  - Export OpenAPI Surface: downloads parsed endpoint inventory as JSON.

---

### Screen 06: Scan Audit History (`06-scan-history`)
- **Stitch Screen ID:** `12717aa11140429da16164e10d0c2389`
- **Purpose:** Audit log vault tracking past executions, run durations, severity distributions, and report downloads.
- **Exact API Routes (from `openapi.json`):**
  - `GET /scans`: Paginated list of `ScanSummary` records.
  - `DELETE /scans/{id}`: Deletes a scan record from the JSON snapshot store.
  - `GET /scans/{id}/report.md` & `GET /scans/{id}/report.json`.
- **Exact Response Fields Shown:**
  - `scan_id`, `status` (`COMPLETED`, `RUNNING`, `FAILED`, `CANCELLED`, `INTERRUPTED`).
  - `target_url`, `started_at`, `duration_seconds`.
  - Severity distribution mini-chips (`critical`, `high`, `medium`, `low`, `info`).
- **Interactions:**
  - Click `Open Dashboard`: routes to Results Triage Workspace for that scan ID.
  - Click `Report ▾`: dropdown to download Markdown or JSON report.
  - Click `Delete`: removes scan from vault with confirmation.
  - Filter pills: filter table by status.

---

### Screen 07: System States & Resilience Sheet (`07-states-sheet`)
- **Stitch Screen ID:** `8f006aa2a2304cc2a51a1eace731f785`
- **Purpose:** Design blueprint documenting 7 system resilience states, error handling behaviors, loading skeletons, and zero-finding empty states.
- **Exact API Routes (from `openapi.json`):**
  - Simulated responses across `GET /scans/{id}`, `GET /scans/{id}/findings`, network connection failures, and error responses.
- **States Cataloged:**
  1. *Loading Skeleton:* Pulse animations across HUD cards, finding rows, and code panels.
  2. *API Unreachable:* `127.0.0.1:8000` connection failure with retry action.
  3. *Scan Failed:* Sanitized connection reset error on target API with lower concurrency suggestion.
  4. *Scan Cancelled:* Graceful abort showing confirmed deletion of 3 test objects.
  5. *Interrupted by Restart:* Safe recovery from `scans.json` snapshot with intact state seal.
  6. *404 Scan Not Found:* Retention policy eviction notice with vault archive link.
  7. *Findings Empty (Clean Audit):* 150/150 test cases passed with clean compliance report download.

---

## DESIGN-vs-API GAPS List
During design inspection against the active Phase 8 API models, the following architectural gaps were identified. In accordance with Phase 9A rules, **no backend code has been altered in this phase**; these gaps are documented for future enhancement in Phase 9B/10:

| Gap # | Feature / UI Element | Current API State | Proposed Minimal Fix | Needs Backend Change? |
|---|---|---|---|---|
| **GAP-01** | **`verified_controls` Metric** | `ScanSummary` currently returns finding severity totals (`critical`, `high`, `medium`, etc.) but does not expose a count of test cases where access was denied as expected. | Add `verified_controls: int` and `verified_endpoints: list[str]` to `ScanSummary` computed from the test results where `outcome == ALLOW/DENIED` matched ground truth. | **YES** (Backend model addition in Phase 9B/10) |
| **GAP-02** | **Top-Level `risk_breakdown` on Finding** | The four component risk scores (Impact, Exploitability, Data Sensitivity, Evidence Strength) are computed in `risk.py` and stored inside `evidence.response_diff["risk_breakdown"]` rather than top-level fields on `Finding`. | Either promote `risk_breakdown: dict[str, int]` to a first-class field on `Finding`, or document that Phase 9B frontend parses it from `finding.evidence.response_diff.risk_breakdown`. | **NO** (Can be read directly from `evidence.response_diff`, though promoting to top-level is cleaner) |
| **GAP-03** | **Endpoint Risk Score in Surface API** | `GET /scans/{id}/surface` returns `list[Endpoint]` as parsed from OpenAPI, but does not include the integer risk priority score calculated by `risk_prioritizer.py`. | Add `priority_score: int = 50` to `Endpoint` schema in `app/models.py` populated during surface mapping. | **YES** (Backend model addition in Phase 9B/10) |
| **GAP-04** | **cURL Suite Export Route** | UI Export menu offers "cURL Attack Suite". Currently, API offers `/report.md` and `/report.json`. | Assemble the cURL suite client-side in Phase 9B by extracting `finding.curl_poc` from each finding in `GET /scans/{id}/findings`. | **NO** (Client-side aggregation in Phase 9B) |

---

## Design QA & Verification Checklist (Task 5)

| Screen Name | Visual Anchor & Theme | Mandatory Corrections Applied | All Task 3 Elements Present | Stitch Passes Used | QA Status |
|---|---|---|---|---|---|
| **01 Results Triage Workspace** | Tactical Cyber Reconnaissance (`#06080F`, `#0D111C`, `#38BDF8`) | No CVSS/CWE, $TOKEN used, 5 severities, masked secrets | Status bar, HUD cards, filter pills, search, finding cards, dual-identity diff, 4-bar risk, cURL console, fix hint, AI section | 1 pass | **PASS** |
| **02 New Scan Configuration** | Consistent dark theme & component tokens | No CVSS/CWE, passwords never stored disclaimer | Spec URL/JSON tab, base URL, 3 identity rows, 6 check toggles, budget slider, auth checkbox, scope guard, validation error | 1 pass | **PASS** |
| **03 Live Scan Progress** | Consistent dark theme & monospace logs | No CVSS/CWE, $TOKEN used, zero secrets | 8-stage stepper, 68% progress bar, request budget, elapsed time, live monospace event log, per-check chips, cancel button | 1 pass | **PASS** |
| **04 Authorization Matrix** | Consistent dark theme & heatmap styling | No CVSS/CWE, zero credentials | 7 object rows, 4 personas, 4 cell states (OWNS, ALLOWED, DENIED, VIOLATION in red), legend, resource filter, warning caption | 1 pass | **PASS** |
| **05 Attack Surface** | Consistent dark theme & table styles | No CVSS/CWE, zero tokens | Sortable table, method chips, monospace paths, auth icons, object/priv badges, resource category, priority bars | 1 pass | **PASS** |
| **06 Scan History** | Consistent dark theme & table styles | No CVSS/CWE, zero tokens | 5 status rows (completed, running, failed, cancelled, interrupted), host, started, duration, severity mini-chips, empty state preview | 1 pass | **PASS** |
| **07 States Sheet** | Consistent dark theme & catalog cards | No CVSS/CWE, zero tokens | Loading skeleton, API unreachable, scan failed, cancelled, interrupted by restart, 404 scan not found, findings empty state | 1 pass | **PASS** |
