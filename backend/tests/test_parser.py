"""Comprehensive unit tests for the OpenAPI parser and surface mapper."""

import json
from pathlib import Path

import httpx
import pytest

from app.config import ScopeViolationError, Settings
from app.parser.openapi_loader import (
    SpecLoadError,
    SpecValidationError,
    load_spec,
    resolve_and_validate,
)
from app.parser.risk_prioritizer import prioritize, score_endpoint
from app.parser.surface_mapper import (
    build_attack_surface,
    infer_resource,
    is_object_level_endpoint,
    is_privileged_endpoint,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_infer_resource_cases() -> None:
    """Verify resource inference and singularization logic."""
    assert infer_resource("/orders") == "order"
    assert infer_resource("/orders/{id}") == "order"
    assert infer_resource("/admin/users") == "user"
    assert infer_resource("/categories/{id}") == "category"
    assert infer_resource("/health") is None
    assert infer_resource("/auth/login") is None
    assert infer_resource("/_reset") is None
    assert infer_resource("/addresses") == "address"


@pytest.mark.asyncio
async def test_target_spec_parsing() -> None:
    """Ensure target_openapi.json parses cleanly and meets all structural requirements."""
    spec_path = FIXTURES_DIR / "target_openapi.json"
    raw_spec = await load_spec(spec_path)
    resolved = resolve_and_validate(raw_spec)
    endpoints = build_attack_surface(resolved)

    # 1. At least 12 endpoints discovered
    assert len(endpoints) >= 12

    by_path_method = {(e.method, e.path): e for e in endpoints}

    # 2. GET/PUT/DELETE /orders/{id} and GET /users/{id} are object-level and require auth
    for method in ("GET", "PUT", "DELETE"):
        ep = by_path_method.get((method, "/orders/{id}"))
        assert ep is not None, f"Missing {method} /orders/{{id}}"
        assert ep.is_object_level is True
        assert ep.requires_auth is True

    user_ep = by_path_method.get(("GET", "/users/{id}"))
    assert user_ep is not None
    assert user_ep.is_object_level is True
    assert user_ep.requires_auth is True

    # 3. GET /admin/users is privileged
    admin_ep = by_path_method.get(("GET", "/admin/users"))
    assert admin_ep is not None
    assert admin_ep.is_privileged is True

    # 4. Products endpoints are not auth-required; /products/{id} is object-level but scores below /orders/{id}
    prod_list = by_path_method.get(("GET", "/products"))
    assert prod_list is not None
    assert prod_list.requires_auth is False

    prod_item = by_path_method.get(("GET", "/products/{id}"))
    assert prod_item is not None
    assert prod_item.requires_auth is False
    assert prod_item.is_object_level is True

    order_get = by_path_method[("GET", "/orders/{id}")]
    assert score_endpoint(prod_item) < score_endpoint(order_get)

    # 5. GET /reports/summary requires_auth is True (declared in spec)
    reports_ep = by_path_method.get(("GET", "/reports/summary"))
    assert reports_ep is not None
    assert reports_ep.requires_auth is True

    # 6. POST /auth/login is not auth-required; resource is None
    login_ep = by_path_method.get(("POST", "/auth/login"))
    assert login_ep is not None
    assert login_ep.requires_auth is False
    assert login_ep.resource is None


@pytest.mark.asyncio
async def test_minimal_spec_security_overrides() -> None:
    """Ensure operation-level security overrides global security in minimal_openapi3.yaml."""
    spec_path = FIXTURES_DIR / "minimal_openapi3.yaml"
    raw_spec = await load_spec(spec_path)
    resolved = resolve_and_validate(raw_spec)
    endpoints = build_attack_surface(resolved)

    by_path_method = {(e.method, e.path): e for e in endpoints}

    # /public-info has security: [] -> public override
    public_ep = by_path_method.get(("GET", "/public-info"))
    assert public_ep is not None
    assert public_ep.requires_auth is False

    # /items inherits global bearerAuth -> requires_auth True
    items_ep = by_path_method.get(("GET", "/items"))
    assert items_ep is not None
    assert items_ep.requires_auth is True


@pytest.mark.asyncio
async def test_prioritizer_ordering() -> None:
    """Ensure prioritize puts write object-level endpoints above public ones and utility paths last."""
    spec_path = FIXTURES_DIR / "target_openapi.json"
    raw_spec = await load_spec(spec_path)
    resolved = resolve_and_validate(raw_spec)
    endpoints = build_attack_surface(resolved)
    prioritized = prioritize(endpoints)

    top_endpoints = [f"{e.method} {e.path}" for e in prioritized[:5]]
    bottom_endpoints = [f"{e.method} {e.path}" for e in prioritized[-3:]]

    # Write object level (e.g. PUT/DELETE /orders/{id}) and privileged routes rank near top
    assert any("PUT /orders/{id}" in ep or "DELETE /orders/{id}" in ep or "GET /admin/users" in ep for ep in top_endpoints)

    # Utility paths rank at the very bottom
    assert any("/health" in ep for ep in bottom_endpoints)
    assert any("/_reset" in ep for ep in bottom_endpoints)


@pytest.mark.asyncio
async def test_loader_scope_violation() -> None:
    """Ensure loader rejects out-of-scope URLs before initiating network requests."""
    settings = Settings(ALLOWED_HOSTS=["localhost", "127.0.0.1", "target_api"])
    with pytest.raises(ScopeViolationError):
        await load_spec("https://malicious.example.com/openapi.json", settings=settings)


def test_validator_rejects_invalid_spec() -> None:
    """Ensure resolve_and_validate raises SpecValidationError on malformed specs."""
    invalid_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Missing Version"},
        # Missing required 'paths' element
    }
    with pytest.raises(SpecValidationError):
        resolve_and_validate(invalid_spec)


@pytest.mark.asyncio
async def test_loader_rejects_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure loader rejects remote payloads exceeding 10 MB limit."""
    settings = Settings(ALLOWED_HOSTS=["localhost", "127.0.0.1", "target_api"])

    # Mock an 11 MB response
    big_content = b"a" * (11 * 1024 * 1024)

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            content=big_content,
            headers={"content-length": str(len(big_content))},
        )

    transport = httpx.MockTransport(mock_handler)

    # Patch httpx.AsyncClient to use MockTransport
    orig_client = httpx.AsyncClient

    def patched_client(*args, **kwargs):
        kwargs["transport"] = transport
        return orig_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", patched_client)

    with pytest.raises(SpecLoadError, match="exceeds maximum allowed size"):
        await load_spec("http://localhost:8000/big_spec.json", settings=settings)
