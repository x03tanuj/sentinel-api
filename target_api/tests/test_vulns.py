"""Comprehensive tests for Target API security flaws and fixes."""

import pytest
from fastapi.testclient import TestClient

from app.data import reset_data
from app.main import app


@pytest.fixture(autouse=True)
def setup_teardown() -> None:
    """Reset data before and after each test execution."""
    reset_data()
    yield
    reset_data()


@pytest.fixture
def client() -> TestClient:
    """Provide FastAPI test client."""
    return TestClient(app)


def get_auth_token(client: TestClient, username: str = "userA", password: str = "passA123") -> str:
    """Helper to authenticate and return a bearer JWT token."""
    res = client.post("/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, f"Login failed for {username}: {res.text}"
    return res.json()["access_token"]


@pytest.mark.parametrize("secure_val", ["false", "true"])
def test_bola_read(client: TestClient, monkeypatch: pytest.MonkeyPatch, secure_val: str) -> None:
    """Test BOLA read vulnerability on /orders/{id}."""
    monkeypatch.setenv("SECURE", secure_val)
    token_a = get_auth_token(client, "userA", "passA123")
    token_b = get_auth_token(client, "userB", "passB123")

    # Order 104 belongs to userB (user_id 2). UserA attempts to read it.
    res_a = client.get("/orders/104", headers={"Authorization": f"Bearer {token_a}"})
    if secure_val == "false":
        # VULN: UserA can read UserB's order
        assert res_a.status_code == 200
        assert res_a.json()["id"] == 104
        assert res_a.json()["user_id"] == 2
    else:
        # FIX: UserA is forbidden from accessing UserB's order
        assert res_a.status_code == 403

    # In both modes, owner (userB) can read their own order
    res_b = client.get("/orders/104", headers={"Authorization": f"Bearer {token_b}"})
    assert res_b.status_code == 200
    assert res_b.json()["user_id"] == 2


@pytest.mark.parametrize("secure_val", ["false", "true"])
def test_bola_write_put(client: TestClient, monkeypatch: pytest.MonkeyPatch, secure_val: str) -> None:
    """Test BOLA write (PUT) vulnerability on /orders/{id}."""
    monkeypatch.setenv("SECURE", secure_val)
    token_a = get_auth_token(client, "userA", "passA123")

    # UserA attempts to modify UserB's order 104
    payload = {"shipping_address": "Tampered Address 999"}
    res = client.put("/orders/104", json=payload, headers={"Authorization": f"Bearer {token_a}"})

    if secure_val == "false":
        # VULN: UserA successfully modifies UserB's order
        assert res.status_code == 200
        assert res.json()["shipping_address"] == "Tampered Address 999"
    else:
        # FIX: UserA is blocked
        assert res.status_code == 403


@pytest.mark.parametrize("secure_val", ["false", "true"])
def test_bola_write_delete(client: TestClient, monkeypatch: pytest.MonkeyPatch, secure_val: str) -> None:
    """Test BOLA write (DELETE) vulnerability on /orders/{id}."""
    monkeypatch.setenv("SECURE", secure_val)
    token_a = get_auth_token(client, "userA", "passA123")

    # UserA attempts to delete UserB's order 104
    res = client.delete("/orders/104", headers={"Authorization": f"Bearer {token_a}"})

    if secure_val == "false":
        # VULN: UserA successfully deletes order
        assert res.status_code == 204
    else:
        # FIX: UserA is forbidden
        assert res.status_code == 403


@pytest.mark.parametrize("secure_val", ["false", "true"])
def test_excessive_data_exposure(client: TestClient, monkeypatch: pytest.MonkeyPatch, secure_val: str) -> None:
    """Test Excessive Data Exposure and BOLA on /users/{id}."""
    monkeypatch.setenv("SECURE", secure_val)
    token_a = get_auth_token(client, "userA", "passA123")

    # UserA fetches UserB's record (id 2)
    res_b = client.get("/users/2", headers={"Authorization": f"Bearer {token_a}"})

    if secure_val == "false":
        # VULN: Leaks full user record including password_hash and ssn
        assert res_b.status_code == 200
        data = res_b.json()
        assert "password_hash" in data
        assert "ssn" in data
        assert data["ssn"] == "444-55-6666"
    else:
        # FIX: Blocked from accessing other user's record
        assert res_b.status_code == 403

        # In secure mode, accessing own profile exposes only safe fields
        res_own = client.get("/users/1", headers={"Authorization": f"Bearer {token_a}"})
        assert res_own.status_code == 200
        own_data = res_own.json()
        assert "password_hash" not in own_data
        assert "ssn" not in own_data
        assert own_data["email"] == "userA@example.com"


@pytest.mark.parametrize("secure_val", ["false", "true"])
def test_bfla_admin_users(client: TestClient, monkeypatch: pytest.MonkeyPatch, secure_val: str) -> None:
    """Test Broken Function Level Authorization on /admin/users."""
    monkeypatch.setenv("SECURE", secure_val)
    token_a = get_auth_token(client, "userA", "passA123")
    token_admin = get_auth_token(client, "admin", "admin123")

    # Regular userA accesses admin route
    res_user = client.get("/admin/users", headers={"Authorization": f"Bearer {token_a}"})

    if secure_val == "false":
        # VULN: Regular user can access admin endpoint
        assert res_user.status_code == 200
        assert len(res_user.json()) == 3
    else:
        # FIX: Regular user receives 403
        assert res_user.status_code == 403

    # Admin user can always access endpoint
    res_admin = client.get("/admin/users", headers={"Authorization": f"Bearer {token_admin}"})
    assert res_admin.status_code == 200
    assert len(res_admin.json()) == 3


@pytest.mark.parametrize("secure_val", ["false", "true"])
def test_missing_authentication(client: TestClient, monkeypatch: pytest.MonkeyPatch, secure_val: str) -> None:
    """Test missing authentication on /reports/summary."""
    monkeypatch.setenv("SECURE", secure_val)

    # Request without Authorization header
    res = client.get("/reports/summary")

    if secure_val == "false":
        # VULN: Access granted without token
        assert res.status_code == 200
        data = res.json()
        assert "total_orders" in data
        assert "total_revenue" in data
        assert "total_users" in data
    else:
        # FIX: 401 Unauthorized
        assert res.status_code == 401


@pytest.mark.parametrize("secure_val", ["false", "true"])
def test_rate_limiting(client: TestClient, monkeypatch: pytest.MonkeyPatch, secure_val: str) -> None:
    """Test rate limiting on /auth/login during rapid failed attempts."""
    monkeypatch.setenv("SECURE", secure_val)

    responses = []
    for _ in range(15):
        r = client.post("/auth/login", json={"username": "userA", "password": "wrongpassword"})
        responses.append(r.status_code)

    if secure_val == "false":
        # VULN: No rate limit applied, all return 401
        assert all(code == 401 for code in responses)
        assert 429 not in responses
    else:
        # FIX: First 10 return 401, 11th through 15th return 429
        assert responses[:10] == [401] * 10
        assert responses[10:] == [429] * 5


@pytest.mark.parametrize("secure_val", ["false", "true"])
def test_public_products(client: TestClient, monkeypatch: pytest.MonkeyPatch, secure_val: str) -> None:
    """Ensure product catalog endpoints remain public in both modes."""
    monkeypatch.setenv("SECURE", secure_val)

    res_list = client.get("/products")
    assert res_list.status_code == 200
    assert len(res_list.json()) == 5

    res_item = client.get("/products/1")
    assert res_item.status_code == 200
    assert res_item.json()["name"] == "Mechanical Keyboard"


def test_openapi_specification(client: TestClient) -> None:
    """Verify OpenAPI schema conforms to design specifications."""
    res = client.get("/openapi.json")
    assert res.status_code == 200
    spec = res.json()

    # 1. BearerAuth security scheme declared
    sec_schemes = spec.get("components", {}).get("securitySchemes", {})
    assert "bearerAuth" in sec_schemes
    assert sec_schemes["bearerAuth"]["type"] == "http"
    assert sec_schemes["bearerAuth"]["scheme"] == "bearer"

    paths = spec.get("paths", {})

    # 2. Every route has explicit operationId
    for path, methods in paths.items():
        for method, details in methods.items():
            if method in ("get", "post", "put", "delete", "patch"):
                assert "operationId" in details, f"Missing operationId in {method.upper()} {path}"

    # 3. Public endpoints have NO security requirement
    assert "security" not in paths["/products"]["get"]
    assert "security" not in paths["/products/{id}"]["get"]

    # 4. Authenticated endpoints have security declared
    orders_id_sec = paths["/orders/{id}"]["get"].get("security", [])
    assert any("bearerAuth" in s for s in orders_id_sec)

    # 5. /reports/summary explicitly declares bearerAuth
    reports_sec = paths["/reports/summary"]["get"].get("security", [])
    assert any("bearerAuth" in s for s in reports_sec)
