"""Unit tests for resource discovery, ID extraction, and collection querying."""

import httpx
import pytest

from app.config import Settings
from app.engine.discovery import OwnedObject, discover_ownership, extract_id
from app.engine.http_executor import Executor
from app.models import Endpoint, Identity


def test_extract_id_variants() -> None:
    # 1. Exact 'id'
    assert extract_id({"id": 123}) == "123"
    assert extract_id({"id": "abc-456"}) == "abc-456"

    # 2. Resource-specific id (order_id)
    assert extract_id({"order_id": 99}, resource="order") == "99"
    assert extract_id({"orderId": 100}, resource="order") == "100"

    # 3. Uuid
    assert extract_id({"uuid": "1111-2222"}) == "1111-2222"

    # 4. None found
    assert extract_id({"name": "No ID here"}) is None
    assert extract_id({}) is None
    assert extract_id(None) is None  # type: ignore


@pytest.mark.asyncio
async def test_discover_ownership_response_shapes_and_me_path() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.url.path == "/orders":
            # Bare list
            return httpx.Response(200, json=[{"id": 101, "item": "widget"}, {"id": 102, "item": "gadget"}])
        elif request.url.path == "/reports":
            # Wrapped list in items
            return httpx.Response(200, json={"items": [{"id": "rep-1"}, {"id": "rep-2"}]})
        elif request.url.path == "/users/me":
            # Single object
            return httpx.Response(200, json={"id": 42, "username": "alice", "email": "alice@test.com"})
        elif request.url.path == "/products":
            # Public endpoint (should not be probed if requires_auth is False)
            return httpx.Response(200, json=[{"id": 1}])
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    executor = Executor(transport=transport)

    endpoints = [
        Endpoint(method="GET", path="/orders", resource="order", requires_auth=True),
        Endpoint(method="GET", path="/reports", resource="report", requires_auth=True),
        Endpoint(method="GET", path="/users/me", resource="me", requires_auth=True),
        Endpoint(method="GET", path="/products", resource="product", requires_auth=False),  # public
        Endpoint(method="POST", path="/orders", resource="order", requires_auth=True),      # non-GET
    ]

    identities = [
        Identity(name="userA", role="user", token="tokA", user_id=None),
        Identity(name="anonymous", role="anonymous", token=None),
    ]

    owned = await discover_ownership(endpoints, identities, executor, base_url="http://localhost")

    # Anonymous was skipped
    assert "anonymous" not in owned
    assert "userA" in owned

    # Check discovered objects
    orders = owned["userA"]["order"]
    assert len(orders) == 2
    assert {o.object_id for o in orders} == {"101", "102"}

    reports = owned["userA"]["report"]
    assert len(reports) == 2
    assert {o.object_id for o in reports} == {"rep-1", "rep-2"}

    # /users/me mapped as user resource
    users = owned["userA"]["user"]
    assert any(u.object_id == "42" for u in users)

    # Verify non-GET endpoints were never called
    for call in calls:
        assert call.startswith("GET "), f"Non-GET method was called: {call}"


@pytest.mark.asyncio
async def test_discover_ownership_respects_request_cap() -> None:
    settings = Settings(DISCOVERY_MAX_REQUESTS_PER_IDENTITY=2, ALLOWED_HOSTS=["localhost"])
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, json=[{"id": request_count}])

    transport = httpx.MockTransport(handler)
    executor = Executor(settings=settings, transport=transport)

    endpoints = [
        Endpoint(method="GET", path=f"/resource_{i}", resource=f"res_{i}", requires_auth=True)
        for i in range(10)
    ]
    identities = [Identity(name="tester", role="user", token="tok")]

    await discover_ownership(endpoints, identities, executor, base_url="http://localhost")

    # Must be capped at DISCOVERY_MAX_REQUESTS_PER_IDENTITY = 2
    assert request_count == 2
