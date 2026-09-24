"""Unit tests for security test case generation, prioritization, and budget enforcement."""

from app.engine.auth_matrix import MatrixCell, Outcome
from app.engine.discovery import OwnedObject
from app.engine.http_executor import build_url
from app.engine.test_generator import (
    TestCategory,
    generate_adjacent_id_cases,
    generate_all,
    generate_anonymous_cases,
    generate_boundary_cases,
    generate_cross_user_cases,
    generate_invalid_type_cases,
    generate_privileged_cases,
)
from app.models import Endpoint, Identity


def test_generate_cross_user_cases() -> None:
    endpoints = [
        Endpoint(method="GET", path="/orders/{id}", resource="order", is_object_level=True, requires_auth=True),
        Endpoint(method="PUT", path="/orders/{id}", resource="order", is_object_level=True, requires_auth=True),
        Endpoint(method="GET", path="/users/{id}", resource="user", is_object_level=True, requires_auth=True),
    ]

    cells = [
        # userA probing userB's order 202 -> DENY
        MatrixCell(identity="userA", resource="order", object_id="202", owner_identity="userB", expected=Outcome.DENY),
        # userB probing userB's own order 202 -> ALLOW (should NOT produce cross-user case)
        MatrixCell(identity="userB", resource="order", object_id="202", owner_identity="userB", expected=Outcome.ALLOW),
        # userA probing user 2 -> DENY
        MatrixCell(identity="userA", resource="user", object_id="2", owner_identity="userB", expected=Outcome.DENY),
    ]

    cases = generate_cross_user_cases(endpoints, cells)

    # 1 cell for order touching 2 endpoints (GET and PUT) + 1 cell for user touching 1 endpoint (GET) = 3 cases
    assert len(cases) == 3
    for c in cases:
        assert c.category == TestCategory.CROSS_USER
        assert c.expected_outcome == Outcome.DENY
        assert c.identity_name == "userA"


def test_generate_adjacent_id_cases_allow_and_deny_branches() -> None:
    endpoints = [
        Endpoint(method="GET", path="/orders/{id}", resource="order", is_object_level=True),
    ]

    # userA owns 104 and 105
    # For 104: 103 is NOT owned (DENY), 105 IS owned (ALLOW)
    owned = {
        "userA": {
            "order": [
                OwnedObject(resource="order", object_id="104", source_endpoint="/orders"),
                OwnedObject(resource="order", object_id="105", source_endpoint="/orders"),
            ]
        }
    }

    cases = generate_adjacent_id_cases(endpoints, owned)

    # From 104: adjacent 103 (DENY) and 105 (ALLOW)
    # From 105: adjacent 104 (ALLOW) and 106 (DENY)
    case_outcomes = {(c.object_id, c.expected_outcome) for c in cases}
    assert ("103", Outcome.DENY) in case_outcomes
    assert ("105", Outcome.ALLOW) in case_outcomes
    assert ("104", Outcome.ALLOW) in case_outcomes
    assert ("106", Outcome.DENY) in case_outcomes


def test_generate_boundary_cases() -> None:
    endpoints = [
        Endpoint(method="GET", path="/orders/{id}", resource="order", is_object_level=True),
        Endpoint(method="GET", path="/reports", resource="report", is_object_level=False),  # non object-level
    ]
    cases = generate_boundary_cases(endpoints)

    # Only /orders/{id} should have boundary cases (4 values: 0, -1, 999999999, uuid)
    assert len(cases) == 4
    obj_ids = {c.object_id for c in cases}
    assert obj_ids == {"0", "-1", "999999999", "00000000-0000-0000-0000-000000000000"}
    for c in cases:
        assert c.category == TestCategory.BOUNDARY
        assert c.expected_outcome == Outcome.DENY


def test_generate_invalid_type_cases_build_url_compatibility() -> None:
    endpoints = [
        Endpoint(method="GET", path="/orders/{id}", resource="order", is_object_level=True),
    ]
    cases = generate_invalid_type_cases(endpoints)
    assert len(cases) == 4

    # None of the invalid cases should crash build_url from Phase 4
    for c in cases:
        assert c.object_id is not None
        safe_url = build_url("http://localhost:9000", c.endpoint.path, {"id": c.object_id})
        assert "http://localhost:9000/orders/" in safe_url
        assert c.category == TestCategory.INVALID_TYPE
        assert c.expected_outcome == Outcome.DENY


def test_generate_anonymous_cases() -> None:
    endpoints = [
        Endpoint(method="GET", path="/orders/{id}", resource="order", is_object_level=True, requires_auth=True),
        Endpoint(method="GET", path="/reports", resource="report", is_object_level=False, requires_auth=True),
        Endpoint(method="GET", path="/products", resource="product", is_object_level=False, requires_auth=False),
        Endpoint(method="GET", path="/products/{id}", resource="product", is_object_level=True, requires_auth=False),
    ]
    owned = {
        "userA": {
            "order": [OwnedObject(resource="order", object_id="42", source_endpoint="/orders")]
        }
    }
    cases = generate_anonymous_cases(endpoints, owned)

    # Only the 2 requires_auth endpoints
    assert len(cases) == 2
    paths = {c.endpoint.path for c in cases}
    assert paths == {"/orders/{id}", "/reports"}
    assert "/products" not in paths
    assert "/products/{id}" not in paths

    for c in cases:
        assert c.identity_name == "anonymous"
        assert c.category == TestCategory.ANONYMOUS
        assert c.expected_outcome == Outcome.DENY


def test_generate_privileged_cases() -> None:
    endpoints = [
        Endpoint(method="GET", path="/admin/users", resource="user", is_privileged=True, requires_auth=True),
        Endpoint(method="GET", path="/orders", resource="order", is_privileged=False, requires_auth=True),
    ]
    identities = [
        Identity(name="userA", role="user", token="tokA"),
        Identity(name="userB", role="user", token="tokB"),
        Identity(name="admin", role="admin", token="tokAdmin"),  # admin excluded
        Identity(name="anonymous", role="anonymous", token=None),  # anonymous excluded
    ]
    cases = generate_privileged_cases(endpoints, identities)

    # Exactly 2 cases (userA and userB for /admin/users)
    assert len(cases) == 2
    idents = {c.identity_name for c in cases}
    assert idents == {"userA", "userB"}
    for c in cases:
        assert c.endpoint.path == "/admin/users"
        assert c.category == TestCategory.PRIVILEGED_ENDPOINT
        assert c.expected_outcome == Outcome.DENY


def test_generate_all_budget_and_deduplication() -> None:
    endpoints = [
        Endpoint(
            method="PUT",
            path="/orders/{id}",
            resource="order",
            is_object_level=True,
            requires_auth=True,
        ),
        Endpoint(
            method="GET",
            path="/orders/{id}",
            resource="order",
            is_object_level=True,
            requires_auth=True,
        ),
        Endpoint(
            method="GET",
            path="/admin/users",
            resource="user",
            is_privileged=True,
            requires_auth=True,
        ),
    ]
    identities = [
        Identity(name="userA", role="user", token="tokA"),
        Identity(name="userB", role="user", token="tokB"),
        Identity(name="admin", role="admin", token="tokAdmin"),
    ]
    owned = {
        "userA": {"order": [OwnedObject(resource="order", object_id="1", source_endpoint="/orders")]},
        "userB": {"order": [OwnedObject(resource="order", object_id="2", source_endpoint="/orders")]},
    }
    matrix_cells = [
        MatrixCell(identity="userA", resource="order", object_id="2", owner_identity="userB", expected=Outcome.DENY),
        MatrixCell(identity="userB", resource="order", object_id="1", owner_identity="userA", expected=Outcome.DENY),
    ]

    # Test with tight budget of 5
    result = generate_all(endpoints, identities, owned, matrix_cells, budget=5)
    cases, stats = result.cases, result.stats

    assert len(cases) <= 5
    assert stats["total_kept"] <= 5
    assert stats["budget"] == 5

    # CROSS_USER cases must be preserved first
    kept_categories = [c.category for c in cases]
    assert TestCategory.CROSS_USER in kept_categories
    assert stats["kept"][TestCategory.CROSS_USER.value] >= 1
