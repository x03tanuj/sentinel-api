"""Integration tests fetching live OpenAPI specification from target_api."""

import httpx
import pytest

from app.parser.openapi_loader import load_spec, resolve_and_validate
from app.parser.surface_mapper import build_attack_surface


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_target_api_parsing() -> None:
    """Fetch and parse live OpenAPI specification from running target_api container or process."""
    target_url = "http://localhost:9000/openapi.json"
    health_url = "http://localhost:9000/health"

    # Pre-check if service is running
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.get(health_url)
            if resp.status_code != 200:
                pytest.skip("Target API service is not responding with HTTP 200 on localhost:9000")
    except Exception:
        pytest.skip("Target API service is not running or reachable on localhost:9000")

    # Load and parse live specification
    raw_spec = await load_spec(target_url)
    resolved = resolve_and_validate(raw_spec)
    endpoints = build_attack_surface(resolved)

    assert len(endpoints) >= 12
    paths = {e.path for e in endpoints}
    assert "/orders/{id}" in paths
    assert "/admin/users" in paths
    assert "/users/{id}" in paths
