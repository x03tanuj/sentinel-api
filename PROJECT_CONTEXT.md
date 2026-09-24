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
