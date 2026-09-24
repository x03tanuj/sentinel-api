"""Live integration test for full planning pipeline against running target_api."""

import httpx
from pydantic import SecretStr
import pytest

from app.engine.auth_matrix import build_matrix
from app.engine.discovery import discover_ownership
from app.engine.http_executor import Executor
from app.engine.identity import IdentityConfig, IdentityManager
from app.engine.test_generator import TestCategory, generate_all
from app.parser.openapi_loader import load_spec, resolve_and_validate
from app.parser.surface_mapper import build_attack_surface


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_planning_pipeline() -> None:
    """Execute complete end-to-end plan pipeline against live sandboxed target API."""
    base_url = "http://localhost:9000"
    spec_url = f"{base_url}/openapi.json"
    health_url = f"{base_url}/health"

    # Pre-check if service is reachable
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.get(health_url)
            if resp.status_code != 200:
                pytest.skip("Target API is not responding on localhost:9000")
            reset_resp = await client.post(f"{base_url}/_reset")
            assert reset_resp.status_code == 200
    except Exception:
        pytest.skip("Target API service is not running or reachable on localhost:9000")

    # 1. Load and parse spec
    raw_spec = await load_spec(spec_url)
    resolved_spec = resolve_and_validate(raw_spec)
    endpoints = build_attack_surface(resolved_spec)

    async with Executor() as executor:
        mgr = IdentityManager(base_url=base_url, executor=executor)

        configs = [
            IdentityConfig(name="userA", role="user", username="userA", password=SecretStr("passA123")),
            IdentityConfig(name="userB", role="user", username="userB", password=SecretStr("passB123")),
            IdentityConfig(name="admin", role="admin", username="admin", password=SecretStr("admin123")),
        ]
        identities = await mgr.login_all(configs)

        # 2. Discover owned objects
        owned = await discover_ownership(endpoints, identities, executor, base_url=base_url)

        # In target_api seed data, userA has orders 1..3 and userB has orders 4..6
        assert "userA" in owned
        assert "userB" in owned
        assert "order" in owned["userA"]
        assert "order" in owned["userB"]

        userA_orders = {o.object_id for o in owned["userA"]["order"]}
        userB_orders = {o.object_id for o in owned["userB"]["order"]}
        assert len(userA_orders) >= 1
        assert len(userB_orders) >= 1
        # No overlap between users
        assert userA_orders.isdisjoint(userB_orders)

        # 3. Construct authorization matrix
        matrix_cells = build_matrix(owned, identities)
        unique_objects = {(c.resource, c.object_id) for c in matrix_cells}
        # Seed data contains at least 6 orders plus user objects
        assert len(unique_objects) >= 6

        # 4. Generate all test cases
        result = generate_all(endpoints, identities, owned, matrix_cells, budget=150)
        cases, stats = result.cases, result.stats

        assert len(cases) > 0
        assert stats["total_kept"] > 0

        # Assert cross-user cases exist for /orders/{id}
        cross_user_order_cases = [
            c for c in cases
            if c.category == TestCategory.CROSS_USER and c.endpoint.path == "/orders/{id}"
        ]
        assert len(cross_user_order_cases) >= 2

        # Verify cross-user cases pit userA against userB's orders and vice-versa
        userA_probing_B = [c for c in cross_user_order_cases if c.identity_name == "userA"]
        userB_probing_A = [c for c in cross_user_order_cases if c.identity_name == "userB"]
        assert len(userA_probing_B) >= 1
        assert len(userB_probing_A) >= 1
