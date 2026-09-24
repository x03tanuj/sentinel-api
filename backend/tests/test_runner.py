"""Unit tests for the test case runner (MockTransport, safety, caching, budgeting)."""

import httpx
import pytest

from app.config import Settings
from app.engine.auth_matrix import Outcome
from app.engine.context import ScanContext
from app.engine.http_executor import Executor
from app.engine.identity import IdentityManager
from app.engine.runner import run_cases
from app.engine.test_generator import TestCase, TestCategory
from app.models import Endpoint, Identity


def _make_test_context(transport: httpx.MockTransport, settings: Settings | None = None) -> ScanContext:
    base_url = "http://localhost:9000"
    executor = Executor(transport=transport)
    mgr = IdentityManager(base_url=base_url, executor=executor)

    # Register identities in memory
    user_a = Identity(name="userA", role="user", user_id="1", token="fake-token-a")
    user_b = Identity(name="userB", role="user", user_id="2", token="fake-token-b")
    mgr._identities["userA"] = user_a
    mgr._identities["userB"] = user_b

    cfg = settings or Settings()
    return ScanContext(
        base_url=base_url,
        endpoints=[],
        identity_manager=mgr,
        owned={},
        matrix_cells=[],
        cases=[],
        executor=executor,
        settings=cfg,
    )


@pytest.mark.asyncio
async def test_non_get_cases_never_sent_and_noted() -> None:
    """Non-GET test cases must never be dispatched by runner and must be counted in ctx.notes."""
    dispatched_methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        dispatched_methods.append(request.method)
        return httpx.Response(200, json={"id": 101, "owner_id": 1})

    transport = httpx.MockTransport(handler)
    ctx = _make_test_context(transport)

    ep_get = Endpoint(method="GET", path="/orders/{id}", path_params=["id"], resource="order", requires_auth=True)
    ep_post = Endpoint(method="POST", path="/orders", resource="order", requires_auth=True)
    ep_delete = Endpoint(method="DELETE", path="/orders/{id}", path_params=["id"], resource="order", requires_auth=True)

    cases = [
        TestCase(
            category=TestCategory.CROSS_USER,
            endpoint=ep_get,
            identity_name="userB",
            owner_identity="userA",
            object_id="101",
            expected_outcome=Outcome.DENY,
        ),
        TestCase(
            category=TestCategory.CROSS_USER,
            endpoint=ep_post,
            identity_name="userB",
            owner_identity="userA",
            expected_outcome=Outcome.DENY,
        ),
        TestCase(
            category=TestCategory.CROSS_USER,
            endpoint=ep_delete,
            identity_name="userB",
            owner_identity="userA",
            object_id="101",
            expected_outcome=Outcome.DENY,
        ),
    ]

    results = await run_cases(ctx, cases)

    # Only 1 case (GET) should have executed
    assert len(results) == 1
    assert all(m == "GET" for m in dispatched_methods)

    # Verify deferral note
    deferred_notes = [n for n in ctx.notes if "non-GET cases deferred to write-check" in n]
    assert len(deferred_notes) == 1
    assert "2 non-GET cases deferred to write-check" in deferred_notes[0]


@pytest.mark.asyncio
async def test_baseline_caching_single_request() -> None:
    """Baseline requests for (endpoint, owner, object_id) must be fetched exactly once and reused."""
    baseline_requests: list[str] = []
    attack_requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        if "fake-token-a" in auth:
            baseline_requests.append(str(request.url))
            return httpx.Response(200, json={"id": 101, "owner_id": 1, "item": "book"})
        else:
            attack_requests.append(str(request.url))
            return httpx.Response(403, json={"detail": "Forbidden"})

    transport = httpx.MockTransport(handler)
    ctx = _make_test_context(transport)

    ep = Endpoint(method="GET", path="/orders/{id}", path_params=["id"], resource="order", requires_auth=True)

    # Two cases probing the same victim object 101 owned by userA
    cases = [
        TestCase(
            category=TestCategory.CROSS_USER,
            endpoint=ep,
            identity_name="userB",
            owner_identity="userA",
            object_id="101",
            expected_outcome=Outcome.DENY,
        ),
        TestCase(
            category=TestCategory.CROSS_USER,
            endpoint=ep,
            identity_name="anonymous",
            owner_identity="userA",
            object_id="101",
            expected_outcome=Outcome.DENY,
        ),
    ]

    results = await run_cases(ctx, cases)

    # Baseline was fetched ONCE
    assert len(baseline_requests) == 1
    # Both test cases executed and have the cached baseline response attached
    assert len(results) == 2
    for res in results:
        assert res.baseline_response is not None
        assert res.baseline_response.status == 200


@pytest.mark.asyncio
async def test_baseline_non_2xx_yields_none() -> None:
    """If baseline request fails (e.g. 404 or 500), case executes but baseline_response is None."""
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        if "fake-token-a" in auth:
            # Baseline owner call fails with 404
            return httpx.Response(404, json={"detail": "Not found"})
        return httpx.Response(200, json={"id": 999})

    transport = httpx.MockTransport(handler)
    ctx = _make_test_context(transport)

    ep = Endpoint(method="GET", path="/orders/{id}", path_params=["id"], resource="order", requires_auth=True)
    cases = [
        TestCase(
            category=TestCategory.CROSS_USER,
            endpoint=ep,
            identity_name="userB",
            owner_identity="userA",
            object_id="999",
            expected_outcome=Outcome.DENY,
        )
    ]

    results = await run_cases(ctx, cases)
    assert len(results) == 1
    assert results[0].baseline_response is None


@pytest.mark.asyncio
async def test_budget_exhaustion_stops_cleanly() -> None:
    """When budget is exceeded, runner halts cleanly and records a note."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1})

    transport = httpx.MockTransport(handler)
    # Configure executor with MAX_REQUESTS_PER_SCAN=2
    custom_settings = Settings(MAX_REQUESTS_PER_SCAN=2)
    executor = Executor(settings=custom_settings, transport=transport)
    base_url = "http://localhost:9000"
    mgr = IdentityManager(base_url=base_url, executor=executor)
    mgr._identities["userB"] = Identity(name="userB", role="user", user_id="2", token="tok")

    ctx = ScanContext(
        base_url=base_url,
        endpoints=[],
        identity_manager=mgr,
        owned={},
        matrix_cells=[],
        cases=[],
        executor=executor,
        settings=Settings(),
    )

    ep = Endpoint(method="GET", path="/orders/{id}", path_params=["id"], resource="order", requires_auth=True)
    # 5 test cases
    cases = [
        TestCase(
            category=TestCategory.ADJACENT_ID,
            endpoint=ep,
            identity_name="userB",
            object_id=str(100 + i),
            expected_outcome=Outcome.DENY,
        )
        for i in range(5)
    ]

    results = await run_cases(ctx, cases)

    # Should have stopped cleanly after budget exhausted
    assert len(results) <= 2
    budget_notes = [n for n in ctx.notes if "Budget exceeded" in n]
    assert len(budget_notes) >= 1
