"""Script to export Target API OpenAPI 3.x specification to JSON fixture."""

import json
import sys
from pathlib import Path

# Add project root and target_api to sys.path
root_dir = Path(__file__).resolve().parent.parent
target_api_dir = root_dir / "target_api"
sys.path.insert(0, str(target_api_dir))

from app.main import app

fixtures_dir = root_dir / "backend" / "tests" / "fixtures"
fixtures_dir.mkdir(parents=True, exist_ok=True)
output_path = fixtures_dir / "target_openapi.json"

openapi_schema = app.openapi()
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(openapi_schema, f, indent=2)

print(f"Exported target OpenAPI specification to: {output_path}")
