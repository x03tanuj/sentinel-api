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

