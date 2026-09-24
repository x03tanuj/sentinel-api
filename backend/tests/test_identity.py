"""Unit tests for IdentityManager, IdentityConfig, and token/credential protection."""

import httpx
import jwt
from pydantic import SecretStr
import pytest

from app.engine.errors import IdentityNotFoundError, LoginFailedError
from app.engine.http_executor import Executor
from app.engine.identity import ANONYMOUS, IdentityConfig, IdentityManager


def _create_mock_jwt(sub: str, role: str, username: str) -> str:
    """Helper to generate signed test JWT tokens."""
    payload = {
        "sub": sub,
        "role": role,
        "username": username,
    }
    return jwt.encode(payload, "test_secret_key_32_bytes_long_ok!!", algorithm="HS256")


@pytest.mark.asyncio
async def test_identity_manager_successful_login() -> None:
    token_user_a = _create_mock_jwt(sub="user-uuid-111", role="editor", username="userA")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/login":
            return httpx.Response(200, json={"access_token": token_user_a, "token_type": "bearer"})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    executor = Executor(transport=transport)
    mgr = IdentityManager(base_url="http://localhost:9000", executor=executor)

    cfg = IdentityConfig(
        name="userA",
        role="user",  # token claim 'editor' will override this
        username="userA",
        password=SecretStr("supersecretpassword123"),
    )

    ident = await mgr.login(cfg)
    assert ident.name == "userA"
    assert ident.user_id == "user-uuid-111"
    assert ident.role == "editor"
    assert ident.token == token_user_a

    # Test get()
    fetched = mgr.get("userA")
    assert fetched.name == "userA"
    assert fetched.user_id == "user-uuid-111"


@pytest.mark.asyncio
async def test_identity_manager_login_failure_does_not_leak_secrets() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "Invalid credentials provided for admin account"})

    transport = httpx.MockTransport(handler)
    executor = Executor(transport=transport)
    mgr = IdentityManager(base_url="http://localhost:9000", executor=executor)

    cfg = IdentityConfig(
        name="badUser",
        username="badUser",
        password=SecretStr("super_confidential_pass_456"),
    )

    with pytest.raises(LoginFailedError) as exc_info:
        await mgr.login(cfg)

    err_msg = str(exc_info.value)
    # Must NOT contain password
    assert "super_confidential_pass_456" not in err_msg
    # Must NOT leak response body content
    assert "Invalid credentials provided" not in err_msg
    assert "badUser" in err_msg


@pytest.mark.asyncio
async def test_identity_manager_login_all_aggregation() -> None:
    token_valid = _create_mock_jwt(sub="u1", role="user", username="validUser")

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        body = json.loads(request.read())
        if body.get("username") == "validUser":
            return httpx.Response(200, json={"access_token": token_valid})
        return httpx.Response(401, json={"error": "unauthorized"})

    transport = httpx.MockTransport(handler)
    executor = Executor(transport=transport)
    mgr = IdentityManager(base_url="http://localhost:9000", executor=executor)

    cfgs = [
        IdentityConfig(name="valid1", username="validUser", password=SecretStr("p1")),
        IdentityConfig(name="failed1", username="wrongUser1", password=SecretStr("p2")),
        IdentityConfig(name="failed2", username="wrongUser2", password=SecretStr("p3")),
    ]

    with pytest.raises(LoginFailedError) as exc_info:
        await mgr.login_all(cfgs)

    err_msg = str(exc_info.value)
    assert "failed1" in err_msg
    assert "failed2" in err_msg
    assert "valid1" not in err_msg


def test_identity_manager_anonymous_and_unknown_lookup() -> None:
    executor = Executor()
    mgr = IdentityManager(base_url="http://localhost:9000", executor=executor)

    anon = mgr.get("anonymous")
    assert anon.name == "anonymous"
    assert anon.role == "anonymous"
    assert anon.token is None
    assert anon.user_id is None

    with pytest.raises(IdentityNotFoundError, match="Identity 'ghost' not found"):
        mgr.get("ghost")


def test_identity_and_config_repr_never_leaks_secrets() -> None:
    cfg = IdentityConfig(
        name="alice",
        username="alice",
        password=SecretStr("my_sensitive_password"),
    )
    # Pydantic SecretStr masks in repr/str
    assert "my_sensitive_password" not in repr(cfg)
    assert "my_sensitive_password" not in str(cfg)

    ident = mgr_ident = ANONYMOUS.model_copy(update={"token": "super_secret_token_12345"})
    assert "super_secret_token_12345" not in repr(ident)
    assert "super_secret_token_12345" not in str(ident)
    assert "token" not in ident.model_dump()

    mgr = IdentityManager(base_url="http://localhost:9000", executor=Executor())
    mgr._identities["alice"] = ident
    mgr_repr = repr(mgr)
    assert "super_secret_token_12345" not in mgr_repr
    assert "alice" in mgr_repr
