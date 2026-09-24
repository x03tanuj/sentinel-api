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


