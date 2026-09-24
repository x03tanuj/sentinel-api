"""Script to export Scanner FastAPI OpenAPI specification to frontend/src/api/openapi.json."""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Add backend directory to sys.path
root_dir = Path(__file__).resolve().parent.parent
backend_dir = root_dir / "backend"
sys.path.insert(0, str(backend_dir))

from app.main import app

output_dir = root_dir / "frontend" / "src" / "api"
output_dir.mkdir(parents=True, exist_ok=True)
output_path = output_dir / "openapi.json"

openapi_schema = app.openapi()
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(openapi_schema, f, indent=2)

print(f"Exported scanner OpenAPI schema to: {output_path}")
