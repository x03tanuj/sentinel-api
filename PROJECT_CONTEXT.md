Stack: Python 3.11, FastAPI, Pydantic v2, pydantic-settings, httpx, prance, openapi-spec-validator, pytest, pytest-asyncio; React + Vite + Tailwind + Recharts (later phases); Docker Compose. LLM via Groq/OpenRouter (later, explanation only, never detection). No MongoDB for now.

Target repo layout:
sentinelapi/
  PROJECT_CONTEXT.md
  README.md
  docker-compose.yml
  .gitignore
  .env.example
  target_api/                  # deliberately vulnerable demo API (Phase 2)
  backend/
    Dockerfile
    requirements.txt
    pytest.ini
    app/
      __init__.py
      main.py
      models.py
      config.py
      store.py                 # placeholder for now
      parser/__init__.py
      engine/__init__.py
      engine/checks/__init__.py
      ai/__init__.py
    tests/
      __init__.py
      test_config.py
      test_models.py
  frontend/                    # placeholder README only for now

Coding rules: type hints everywhere, small pure functions, docstrings on public functions, no secrets written to disk, redact tokens in all logs and evidence, every module gets pytest tests. Always give complete files, never snippets.

## Standing rules

1. MCP usage: Use every MCP server available in this workspace whenever it helps, instead of guessing or relying on memory. Specifically:
   - Docs MCP (e.g. Context7): before using any library API (prance, openapi-spec-validator, httpx, FastAPI, pydantic v2, PyJWT), look up the current docs and use the documented API.
   - GitHub MCP: use it for repository operations (checking the remote, pushing, tagging, creating the release/tag) when available.
   - Any filesystem, browser, or terminal MCP: use them for verification (for example, opening the running service and checking output).
   At the end of each phase, list which MCP tools you used and for what. If no MCP servers are available, say so and continue with normal tools.
2. GitHub workflow: the remote is https://github.com/x03tanuj/sentinel-api.git and the branch is main. At the END of every phase: run the full test suite, make sure no secrets or .env files are staged, commit with the message "phase N: <short description>", push to origin main, and create a lightweight tag "phase-N" and push it. Never embed tokens or passwords in the remote URL, commands, or files. If authentication fails, stop and tell me exactly what to run manually instead of trying workarounds.
3. Before every commit: `git status` and `git diff --stat` reviewed, and confirm .env, data/, __pycache__, .venv, node_modules are ignored.
4. Keep all earlier acceptance checks passing (regression). Re-run earlier test suites at the end of each phase.

## Phase 3 completed
Implemented the OpenAPI specification parser, schema validator/dereferencer, risk prioritization engine, and attack surface mapper.
Public API functions:
- `load_spec(source: str | dict | Path, settings: Settings | None = None) -> dict`: Loads OpenAPI specs from dicts, local JSON/YAML files, or sandboxed HTTP/HTTPS URLs with strict scope validation and 10 MB payload limits.
- `resolve_and_validate(spec: dict) -> dict`: Validates specs against OpenAPI standards via `openapi_spec_validator` and resolves schema `$ref` pointers with circular-reference protection.
- `build_attack_surface(spec: dict) -> list[Endpoint]`: Maps endpoints to `Endpoint` models with resolved schemas, merged parameters, auth requirement detection, resource inference, and object-level/privileged flags.
- `prioritize(endpoints: list[Endpoint]) -> list[Endpoint]`: Sorts endpoints in descending order of risk score (state-changing object writes and privileged routes first, public unprivileged routes and utility routes last).
- `describe_surface(endpoints: list[Endpoint]) -> str`: Renders a formatted Rich table displaying endpoints, auth requirements, object/privileged flags, inferred resources, and scores.

## Phase 4 completed
Implemented identity management, authentication orchestration, and the guarded HTTP execution engine.

Public classes and functions:
- `Executor.execute(method, url, identity=None, params=None, json_body=None, extra_headers=None) -> tuple[RequestRecord, ResponseRecord]`: Safely dispatches rate-limited HTTP probe requests through a token-bucket rate limiter, scope guard (`assert_in_scope`), request budget cap (`MAX_REQUESTS_PER_SCAN`), and streaming size truncation (`MAX_RESPONSE_BYTES`). Returns redacted RequestRecord and in-memory ResponseRecord.
- `build_url(base_url: str, path_template: str, path_params=None, query=None) -> str`: Safely constructs complete URLs with percent-encoded path params (`safe=""`) to prevent path traversal.
- `generate_curl(request: RequestRecord) -> str`: Generates shell-safe, copy-pasteable curl commands using `$TOKEN` placeholders for bearer credentials.
- `IdentityManager(base_url, executor)`: In-memory identity registry managing test personas.
  - `login(cfg: IdentityConfig) -> Identity`: Authenticates persona against target API and extracts user_id/role from JWT without signature verification.
  - `login_all(configs: list[IdentityConfig]) -> list[Identity]`: Sequentially authenticates personas and raises aggregate `LoginFailedError` on any failure.
  - `get(name: str) -> Identity`: Resolves registered identities or `anonymous`.
- `redact_headers(headers: Mapping) -> dict`: Case-insensitively scrubs sensitive headers (`Authorization`, `Cookie`, `X-Api-Key`, etc.).
- `redact_body(body: Any) -> Any`: Recursively scrubs fields matching sensitive keys (`password`, `token`, `secret`, `api_key`).
- `redact_response(resp: ResponseRecord) -> ResponseRecord`: Returns a copy with scrubbed headers and body.
- `mask_value(v: str) -> str`: Preserves first 2 and last 2 characters (e.g. `11*******33`) for evidence reporting.

Core Rule:
All scanner traffic MUST go through `Executor.execute`; raw ResponseRecords stay in memory; anything user-facing must be redacted or masked.

## Phase 5 completed
Implemented resource discovery, ground-truth authorization matrix construction, and prioritized, budget-capped test case generation.

Public classes and functions:
- `discover_ownership(endpoints, identities, executor, base_url="http://localhost:9000") -> dict[str, dict[str, list[OwnedObject]]]`: Queries legitimate collection GET and profile endpoints (/users/me) per identity without guessing IDs, learning owned resource objects up to `DISCOVERY_MAX_REQUESTS_PER_IDENTITY`.
- `discover_via_creation(endpoints, identity, executor, sample_bodies, base_url="http://localhost:9000") -> list[OwnedObject]`: Opt-in object creation via POST endpoints for test setups, tracking created objects for subsequent testing and cleanup.
- `build_matrix(owned, identities) -> list[MatrixCell]`: Constructs an authorization matrix mapping every known (resource, object_id) to each identity with ground-truth expected outcomes (`ALLOW` for owner or admin, `DENY` otherwise).
- `render_matrix(cells, identities) -> str`: Visualizes the authorization matrix as a formatted Rich table (own/admin/deny per persona).
- `generate_all(endpoints, identities, owned, matrix_cells, budget=150) -> GenerationResult`: Prioritizes, deduplicates, and caps test cases across six categories (CROSS_USER, PRIVILEGED_ENDPOINT, ADJACENT_ID, BOUNDARY, ANONYMOUS, INVALID_TYPE), guaranteeing CROSS_USER and PRIVILEGED_ENDPOINT cases are preserved before trimming.

Core Rule:
`generate_all` is the single entry point Phase 6 must call to get TestCases; it already respects the request budget.

## Phase 6 completed
Implemented the differential analysis engine, test case runner, modular security check suite, and automated vulnerability scanning pipeline.

Public classes and functions:
- `compare(baseline: ResponseRecord | None, attack: ResponseRecord, attacker: Identity | None = None, requested_object_id: str | None = None) -> DiffResult`: Differential response analyzer computing weighted Jaccard similarity for JSON payloads, difflib ratio for text, owner ID divergence, sensitive field classification, and soft-fail error detection.
- `DiffResult`: Pydantic model encapsulating status changes, body/schema similarity scores, owner divergence, same-object validation, and sensitive fields exposed.
- `run_cases(ctx: ScanContext, cases: list[TestCase]) -> list[CaseResult]`: Throttled test runner executing GET cases via `asyncio.Semaphore(CASE_CONCURRENCY)`, caching legitimate baselines per (endpoint, owner, object_id), and safely deferring write operations.
- `BaseCheck`: Abstract base class defining check interface (`run(ctx: ScanContext) -> list[Finding]`), name, owasp_id, and description.
- `CHECKS`: Global registry mapping check names to check instances (`bola`, `bfla`, `data_exposure`, `rate_limit`, `unauth_access`, `input_handling`).
- `run_checks(ctx: ScanContext, enabled: list[str] | None = None) -> list[Finding]`: Execution harness running checks concurrently with timeout isolation, running `rate_limit` sequentially last, filtering findings below `MIN_REPORT_CONFIDENCE`, and deduplicating findings on (check, method, path, identity) while recording all `affected_objects`.
- `make_finding(...) -> Finding`: Factory constructing sanitized Finding models with linked Evidence, masked diff summaries, and copy-paste curl PoCs with `$TOKEN` placeholders.
- `cleanup_created(ctx: ScanContext) -> None`: Best-effort cleanup deleting scanner-created objects in a `finally` block to leave zero scan residue behind.

Core Rules:
- Checks return Findings with provisional severity; Phase 7 owns final severity and confidence.
- Write-method BOLA tests (PUT/PATCH/DELETE) run strictly on scanner-created objects, never on pre-existing seed data, and are cleaned up in `finally`.
- `rate_limit` runs last and alone to prevent request bursts from skewing or locking out concurrent test personas.
- All requests flow strictly through `Executor.execute`.
- Zero cleartext tokens or SSNs in serialized findings or evidence.

## Phase 7 completed
Implemented explainable Risk and Confidence engines, structured Evidence builder with defense-in-depth sanitization, empirical live reproduction pipeline, and CLI reporting with component score breakdowns.

Public classes and functions:
- `build_evidence(case_result_or_context, request, baseline_response, attack_response, diff, identity, object_id, expected_status=None) -> Evidence`: Structured evidence builder enforcing defense-in-depth re-redaction of headers/bodies, inferring expected status codes, tracking masked sensitive values, and initializing affected object tracking.
- `curl_for_evidence(evidence: Evidence) -> str`: Thin wrapper exporting sanitized, reproducible curl commands using `$TOKEN` placeholders.
- `compute_severity(finding_inputs: RiskInputs) -> tuple[Severity, int, dict[str, int]]`: Transparent severity calculator summing Impact (0-40), Exploitability (0-25), Data Sensitivity (0-30), and Evidence Strength (0-15) into a 0-100 raw score mapped to standardized severity levels (CRITICAL >= 80, HIGH >= 60, MEDIUM >= 35, LOW >= 15, INFO < 15).
- `compute_confidence(diff: DiffResult | None, category: TestCategory | None, reproduced: bool, reproduction_count: int, base_confidence: float | None = None) -> float`: Dynamic confidence calculator adjusting per-signal base confidence with live reproduction bonuses (+0.05 on 1st repeat, +0.03 for >=2 repeats) and severe penalties (-0.20 on failure), clamped to [0.0, 1.0].
- `reproduce_finding(finding: Finding, ctx: ScanContext, attempts: int = 2) -> Finding`: Re-executes finding requests fresh against the target, refines confidence, and downgrades severity by one level (never below INFO) if reproduction fails entirely.
- `reproduce_top_findings(findings: list[Finding], ctx: ScanContext, top_n: int = 8) -> list[Finding]`: Prioritizes top findings by severity and initial confidence within request budget allowances, documenting skipped findings in `ctx.notes`.
- `run_checks_with_reproduction(ctx: ScanContext, enabled: list[str] | None = None, top_n: int = 8) -> list[Finding]`: Primary scan pipeline wrapper running security checks followed by empirical reproduction of top findings and deferred cleanup of test objects.
- `RiskInputs(BaseModel)`: Input vector encapsulating check name, method, privileged status, auth requirements, sequential ID detection, diff results, and attacker identity role.
- `sequential_ids_bonus(...) -> int`: Helper awarding +5 exploitability points when scanned object IDs form sequential integer sequences.

Core Rule:
Finding.severity and Finding.confidence must always be set via `risk.py`, never hardcoded in a check, except through the documented `provisional_severity` fallback path wrapped in try/except.

## Phase 8 completed
Implemented the unified scan pipeline, atomic JSON snapshot store with secret leak guards, scan scheduler/manager, FastAPI REST and SSE streaming routes, report renderers, and schema export tooling.

Public classes and functions:
- `run_scan(config: ScanConfig, on_progress=None, settings=None, scan_id=None) -> ScanResult`: Unified scan pipeline orchestrating specification loading, attack surface mapping, identity authentication, ownership discovery, matrix planning, check execution with progress callbacks, empirical reproduction, and shielded cleanup.
- `ScanConfig(BaseModel)`: Validated scan configuration enforcing scope verification, identity naming rules, check registry validation, and budget caps.
  - `public_view() -> dict`: Returns sanitized, secret-free scan metadata. Never persists or exposes credentials.
- `ProgressEvent(BaseModel)`: Monotonically increasing progress events with execution stages, percentage weights (0-100), and terminal status.
- `ScanResult(BaseModel)`: Complete aggregated scan output encapsulating redacted findings, attack surface endpoints with risk scores, authorization matrix heatmap, planning stats, telemetry notes, and executive summary.
- `JsonSnapshotStore(ScanStore)`: In-memory store with async lock synchronization, atomic disk persistence (`os.replace`) to `{DATA_DIR}/scans.json`, retention policy (max `MAX_STORED_SCANS`, evicting oldest finished), debounced flushing, automatic corruption recovery (`scans.json.corrupt-<timestamp>`), and startup interruption recovery.
- `assert_no_secrets(payload: str) -> None`: Strict safety guard raising `SecretLeakError` if serialized JSON contains Bearer JWTs, raw JWT token structures, or unredacted passwords.
- `ScanManager(store, settings)`: Central scheduler managing scan execution, enforcing `MAX_CONCURRENT_SCANS` (429 with `Retry-After`), duplicate active `base_url` conflict rejection (409), bounded cancellation with shielded cleanup, and real-time SSE subscriber fan-out via async queues.
- `render_markdown(record: ScanRecord) -> str`: Deterministic Markdown audit report generator with executive summary, severity tables, authorization matrix, findings breakdown, and curl PoC snippets.
- `render_json(record: ScanRecord) -> str`: Deterministic JSON findings export with secret leak validation.
- Routes in `backend/app/routes/scans.py`:
  - `POST /scans`: Submit new scan (202 Accepted, 400 for scope/validation, 409 conflict, 429 concurrency).
  - `GET /scans`: List scan summaries (newest first, paginated).
  - `GET /scans/{id}`: Detailed scan status, progress, public config, and summary.
  - `GET /scans/{id}/findings`: Filterable findings (`severity`, `check`, `min_confidence`, `sort`, `order`).
  - `GET /scans/{id}/findings/{id}`: Retrieve single finding details.
  - `GET /scans/{id}/surface`: Mapped attack surface endpoints with risk score, flags, and resource categories.
  - `GET /scans/{id}/matrix`: Authorization matrix heatmap cells and summary counts.
  - `GET /scans/{id}/notes`: Telemetry notes and execution logs.
  - `GET /scans/{id}/events`: Real-time SSE event stream with past event replay and 15s keep-alive heartbeats.
  - `POST /scans/{id}/cancel`: Cancel ongoing scan with bounded wait for shielded cleanup.
  - `DELETE /scans/{id}`: Remove finished scan from storage.
  - `GET /scans/{id}/report.md`: Download Markdown audit report.
  - `GET /scans/{id}/report.json`: Download JSON findings report.

Core Rules:
- One pipeline for everything: CLI `scan` and FastAPI routes both invoke `run_scan`.
- Credentials protection: Only `ScanConfig.public_view()` is persisted in `store` or returned by the API; raw passwords exist only in the execution task closure and are discarded upon completion.
- Cleanup must be shielded (`asyncio.shield`) so created objects are deleted even when cancelled or timed out.
- Localhost binding: When `SENTINEL_API_KEY` is not set, API is bound strictly to `127.0.0.1`. If set, `X-API-Key` is enforced via constant-time comparison.

## Phase 9A completed
Designed the dashboard UI design system and all 7 screens using Google Stitch MCP, producing design artifacts only (`screenshot.png`, `code.html`, `PROJECT.md`, `DESIGN_SYSTEM.md`, `SCREENS.md`, `BRIEF_USER.md`).

Artifacts location:
- `frontend/design/`:
  - `BRIEF_USER.md`: Visual source of truth and aesthetic foundation.
  - `DESIGN_SYSTEM.md`: Comprehensive tokens, ready-to-paste Tailwind theme snippet, typography, component specs, and WCAG AA rules.
  - `SCREENS.md`: Screen-to-API route mappings, inspector field tables, differential response analysis findings, gap list, and QA checklist.
  - `stitch/PROJECT.md`: Stitch project metadata and screen ID directory.
  - `stitch/01-results-triage-workspace/`: Results Triage Workspace (`screenshot.png`, `code.html`).
  - `stitch/02-new-scan/`: New Scan Configuration Dialog (`screenshot.png`, `code.html`).
  - `stitch/03-live-scan-progress/`: Live Scan Progress & Telemetry Monitor (`screenshot.png`, `code.html`).
  - `stitch/04-authorization-matrix/`: Ground-Truth Authorization Matrix (`screenshot.png`, `code.html`).
  - `stitch/05-attack-surface/`: Discovered Attack Surface (`screenshot.png`, `code.html`).
  - `stitch/06-scan-history/`: Scan Audit History (`screenshot.png`, `code.html`).
  - `stitch/07-states-sheet/`: System States & Resilience Sheet (`screenshot.png`, `code.html`).

Core Implementation Rule:
Phase 9B implements from `frontend/design/` (`BRIEF_USER.md` tokens, `DESIGN_SYSTEM.md`, `SCREENS.md` mapping); use Stitch MCP again only for small refinements.

Identified DESIGN-vs-API Gaps:
1. `verified_controls` Metric (GAP-01): `ScanSummary` does not yet expose a count of test cases where unauthorized access was denied as expected. Proposed fix: add `verified_controls: int` and `verified_endpoints: list[str]` to `ScanSummary`. (Needs backend change in Phase 9B/10).
2. Top-Level `risk_breakdown` on Finding (GAP-02): 4-component risk scores reside in `finding.evidence.response_diff["risk_breakdown"]`. Phase 9B reads from `response_diff` directly, with future option to promote to top-level model field.
3. Endpoint Priority Score in Surface API (GAP-03): `GET /scans/{id}/surface` returns `Endpoint` models without the computed risk rank attached. Proposed fix: add `priority_score: int` to `Endpoint` schema in `app/models.py`. (Needs backend change in Phase 9B/10).
4. cURL Suite Export (GAP-04): UI offers "cURL Attack Suite" export. Assembled client-side from `finding.curl_poc` in Phase 9B.

---

### Phase 10 Completed: AI Analyst (Evidence-Only)

Phase 10 implements an evidence-only AI analysis layer with rigorous data egress controls, prompt injection defenses, deterministic fallbacks, and full UI integration.

#### Public Interfaces (`backend/app/ai/`)
- `build_llm_payload(finding: Finding, framework_hint: str) -> dict`: Redacts all hosts, URLs, secrets, bodies, raw IDs, headers, tokens, and curl commands; packages only check, OWASP id, path template, method, severity, confidence, risk score components, attacker role, expected/actual status, changed/leaked field names, reproduction ratio, fix hint, template explanation, and framework hint.
- `assert_payload_safe(serialized: str) -> None`: Pre-flight regex assertion scanning for JWTs, Bearer tokens, passwords, credentials, SSNs, credit cards, emails, URLs, and IP addresses. Aborts egress with `PayloadNotSafeError` on detection.
- `analyze_finding(finding: Finding, framework_hint: str, provider: LLMProvider, settings: Settings) -> AiAnalysis`: Builds redacted payload, asserts safety, calls provider, validates against Pydantic schema with 1-shot retry on invalid JSON, sanitizes output, and falls back to deterministic template on any failure.
- `summarize_scan(summary: dict, findings: list[Finding], provider: LLMProvider, settings: Settings) -> str`: Generates high-level executive summary from finding counts, check names, and path templates only.
- `suggest_hints(endpoints: list[Endpoint], provider: LLMProvider, settings: Settings) -> AnalystHints`: Scan-time exploration hook; provides opt-in boundary test hints and likely object-level/privileged flags from sanitized endpoint metadata.
- `apply_hints(endpoints: list[Endpoint], hints: AnalystHints) -> list[Endpoint]`: Safely overlays hint metadata onto endpoints without downgrading existing parser flags.
- `get_provider(settings: Settings) -> LLMProvider | None`: Provider factory supporting Groq (`llama-3.1-8b-instant`), OpenRouter (`meta-llama/llama-3.1-8b-instruct:free`), and Google Gemini (`gemini-2.0-flash`).
- `AiAnalysis(BaseModel)`: Output schema enforcing strict string length limits and prohibiting severity or confidence fields.

#### Routes
- `GET /ai/status`: Feature-detection status endpoint (`enabled`, `provider`, `model`, `max_calls_per_scan`). Never leaks keys.
- `POST /scans/{id}/findings/{fid}/explain`: Generates or returns cached finding explanation (503 if unconfigured, 409 if incomplete, 422 if invalid framework, 429 if call cap reached).
- `POST /scans/{id}/explain-top?n=5`: Batch-explains top findings by severity & confidence up to call cap.
- `POST /scans/{id}/ai-summary`: Generates or returns executive scan summary.

#### Config Flags (`backend/app/config.py`)
- `AI_ENABLED` (bool, default `False`)
- `LLM_PROVIDER` (`groq` | `openrouter` | `gemini`, default `groq`)
- `LLM_API_KEY` (`SecretStr | None`, default `None`)
- `LLM_MODEL` (str, default per provider)
- `AI_TIMEOUT_SECONDS` (int, default 30)
- `AI_MAX_CALLS_PER_SCAN` (int, default 15)
- `AI_MAX_OUTPUT_TOKENS` (int, default 900)
- `AI_CONCURRENCY` (int, default 2)

#### Invariable Standing Rules:
1. **The LLM never sees secrets, hosts, bodies or values.**
2. **Findings are immutable except for attaching `ai_analysis`.**
3. **All model output is sanitized and rendered strictly as text (no HTML/markdown injection).**
4. **The entire product functions autonomously with AI disabled.**
5. **AI hints are strictly opt-in (`use_ai_hints: true`), bounded by safety rules, and labeled with `hint_source: "llm"`.**


