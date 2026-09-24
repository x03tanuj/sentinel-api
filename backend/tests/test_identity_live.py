"""Live integration tests for IdentityManager against running target_api."""

import httpx
from pydantic import SecretStr
import pytest

from app.engine.http_executor import Executor
from app.engine.identity import IdentityConfig, IdentityManager


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_identity_login_and_profile_separation() -> None:
    """Verify live authentication, JWT parsing, and session separation against target_api."""
    base_url = "http://localhost:9000"
    health_url = f"{base_url}/health"

    # Pre-check if service is reachable
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.get(health_url)
            if resp.status_code != 200:
                pytest.skip("Target API is not responding with HTTP 200 on localhost:9000")
            # Reset in-memory seed data before test
            reset_resp = await client.post(f"{base_url}/_reset")
            assert reset_resp.status_code == 200
    except Exception:
        pytest.skip("Target API is not running or reachable on localhost:9000")

    async with Executor() as executor:
        mgr = IdentityManager(base_url=base_url, executor=executor)

        cfg_a = IdentityConfig(
            name="userA",
            username="userA",
            password=SecretStr("passA123"),
        )
        cfg_b = IdentityConfig(
            name="userB",
            username="userB",
            password=SecretStr("passB123"),
        )

        ident_a = await mgr.login(cfg_a)
        ident_b = await mgr.login(cfg_b)

        # 1. Assert user_ids were successfully parsed from tokens
        assert ident_a.user_id is not None
        assert ident_b.user_id is not None

        # 2. Assert distinct identities have different user IDs
        assert ident_a.user_id != ident_b.user_id

        # 3. Verify each can fetch their own /users/me profile
        _, resp_me_a = await executor.execute("GET", f"{base_url}/users/me", identity=ident_a)
        assert resp_me_a.status == 200
        assert isinstance(resp_me_a.body, dict)
        assert resp_me_a.body.get("username") == "userA"

        _, resp_me_b = await executor.execute("GET", f"{base_url}/users/me", identity=ident_b)
        assert resp_me_b.status == 200
        assert isinstance(resp_me_b.body, dict)
        assert resp_me_b.body.get("username") == "userB"
