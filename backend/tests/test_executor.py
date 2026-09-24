"""Unit tests for HTTP executor, safety controls, rate limiting, and URL/curl helpers."""

import asyncio
import time
from typing import Any

import httpx
import pytest

from app.config import ScopeViolationError, Settings
from app.engine.errors import BudgetExceededError, TargetUnreachableError
from app.engine.http_executor import Executor, build_url, generate_curl
from app.models import Identity, RequestRecord


def test_build_url_safe_encoding() -> None:
    # 1. Percent-encoding prevents path traversal
    url1 = build_url("http://localhost:9000", "/orders/{id}", {"id": "../admin"})
    assert url1 == "http://localhost:9000/orders/..%2Fadmin"

    url2 = build_url("http://localhost:9000", "/orders/{id}", {"id": "1/../2"})
    assert url2 == "http://localhost:9000/orders/1%2F..%2F2"

    url3 = build_url("http://localhost:9000", "/items/{name}", {"name": "a b"})
    assert url3 == "http://localhost:9000/items/a%20b"

    # 2. Base URL trailing slash handling
    url4 = build_url("http://localhost:9000/", "/users/{id}", {"id": 42})
    assert url4 == "http://localhost:9000/users/42"

    # 3. Missing parameter raises ValueError
    with pytest.raises(ValueError, match="Missing required path parameter: 'id'"):
        build_url("http://localhost:9000", "/orders/{id}", {})

    # 4. Query string appended properly
    url5 = build_url("http://localhost:9000", "/orders", query={"status": "pending", "limit": 10})
    assert url5 == "http://localhost:9000/orders?status=pending&limit=10"


def test_generate_curl_redaction_and_quoting() -> None:
    # Request with authorization and body containing a single quote
    req = RequestRecord(
        method="POST",
        url="http://localhost:9000/orders",
        headers_redacted={
            "Authorization": "Bearer ***REDACTED***",
            "Content-Type": "application/json",
        },
        body={"note": "O'Reilly book purchase"},
    )
    cmd = generate_curl(req)

    # Must contain unquoted $TOKEN in double quotes
    assert '-H "Authorization: Bearer $TOKEN"' in cmd
    # Must NOT contain the literal string '***REDACTED***'
    assert "***REDACTED***" not in cmd
    # Correctly quoted body with single quote
    assert "-d" in cmd
    assert "Reilly" in cmd
    assert "note" in cmd


@pytest.mark.asyncio
async def test_executor_scope_guard_never_touches_transport() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"status": "ok"})

    transport = httpx.MockTransport(handler)
    executor = Executor(transport=transport)

    with pytest.raises(ScopeViolationError):
        await executor.execute("GET", "https://evil.com/api/test")

    assert called is False
    assert executor.requests_sent == 0


@pytest.mark.asyncio
async def test_executor_budget_enforcement() -> None:
    settings = Settings(MAX_REQUESTS_PER_SCAN=3, ALLOWED_HOSTS=["localhost"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    executor = Executor(settings=settings, transport=transport)

    # 3 allowed requests
    for _ in range(3):
        await executor.execute("GET", "http://localhost/test")

    assert executor.requests_sent == 3
    assert executor.budget_remaining == 0

    # 4th request must raise BudgetExceededError
    with pytest.raises(BudgetExceededError):
        await executor.execute("GET", "http://localhost/test")

    # Failed scope checks must not consume budget
    with pytest.raises(ScopeViolationError):
        await executor.execute("GET", "https://unauthorized.org")

    assert executor.requests_sent == 3


@pytest.mark.asyncio
async def test_executor_rate_limiting_sequential_and_concurrent() -> None:
    settings = Settings(MAX_RPS=10, ALLOWED_HOSTS=["localhost"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    executor = Executor(settings=settings, transport=transport)

    # 1. 6 sequential requests should take at least 0.4 seconds (5 intervals of ~0.1s)
    t0 = time.perf_counter()
    for _ in range(6):
        await executor.execute("GET", "http://localhost/seq")
    elapsed_seq = time.perf_counter() - t0
    assert elapsed_seq >= 0.4, f"Sequential requests took only {elapsed_seq:.3f}s"

    # 2. 6 concurrent requests with asyncio.gather must also respect the rate limit
    t1 = time.perf_counter()
    tasks = [executor.execute("GET", "http://localhost/conc") for _ in range(6)]
    await asyncio.gather(*tasks)
    elapsed_conc = time.perf_counter() - t1
    assert elapsed_conc >= 0.4, f"Concurrent requests took only {elapsed_conc:.3f}s"


@pytest.mark.asyncio
async def test_executor_no_redirects() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            302,
            headers={"Location": "https://evil.com/leak"},
            text="Redirecting...",
        )

    transport = httpx.MockTransport(handler)
    executor = Executor(transport=transport)

    req_rec, resp_rec = await executor.execute("GET", "http://localhost/redirect")
    assert resp_rec.status == 302
    assert calls == 1
    assert resp_rec.headers.get("location") == "https://evil.com/leak"


@pytest.mark.asyncio
async def test_executor_response_truncation() -> None:
    settings = Settings(MAX_RESPONSE_BYTES=100, ALLOWED_HOSTS=["localhost"])
    large_payload = b"X" * 500

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=large_payload, headers={"content-type": "text/plain"})

    transport = httpx.MockTransport(handler)
    executor = Executor(settings=settings, transport=transport)

    _, resp_rec = await executor.execute("GET", "http://localhost/large")
    assert resp_rec.size == 100
    assert resp_rec.headers.get("x-sentinel-truncated") == "true"
    assert len(resp_rec.body) == 100


@pytest.mark.asyncio
async def test_executor_json_vs_text_and_network_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/json":
            return httpx.Response(200, json={"key": "value"}, headers={"content-type": "application/json"})
        elif request.url.path == "/text":
            return httpx.Response(200, text="Plain response", headers={"content-type": "text/plain"})
        elif request.url.path == "/timeout":
            raise httpx.ConnectTimeout("Connection timed out")
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    executor = Executor(transport=transport)

    _, resp_json = await executor.execute("GET", "http://localhost/json")
    assert isinstance(resp_json.body, dict)
    assert resp_json.body == {"key": "value"}

    _, resp_text = await executor.execute("GET", "http://localhost/text")
    assert isinstance(resp_text.body, str)
    assert resp_text.body == "Plain response"

    with pytest.raises(TargetUnreachableError, match="unreachable: ConnectTimeout"):
        await executor.execute("GET", "http://localhost/timeout")


@pytest.mark.asyncio
async def test_executor_identity_auth_header_redaction() -> None:
    received_auth_header: str | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal received_auth_header
        received_auth_header = request.headers.get("Authorization")
        return httpx.Response(200, json={"authenticated": True})

    transport = httpx.MockTransport(handler)
    executor = Executor(transport=transport)

    ident = Identity(name="alice", role="user", token="secret_jwt_xyz_123")
    req_rec, resp_rec = await executor.execute("GET", "http://localhost/protected", identity=ident)

    # The wire request had the real token
    assert received_auth_header == "Bearer secret_jwt_xyz_123"
    # But returned RequestRecord is redacted
    assert req_rec.headers_redacted["Authorization"] == "Bearer ***REDACTED***"

    # Anonymous request sends no authorization header
    anon = Identity(name="anonymous", role="anonymous", token=None)
    req_anon, _ = await executor.execute("GET", "http://localhost/public", identity=anon)
    assert "Authorization" not in req_anon.headers_redacted
    assert "authorization" not in req_anon.headers_redacted


@pytest.mark.asyncio
async def test_executor_audit_log_cleanliness() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": "sensitive"})

    transport = httpx.MockTransport(handler)
    executor = Executor(transport=transport)

    ident = Identity(name="tester", role="user", token="tok123")
    await executor.execute("POST", "http://localhost/action", identity=ident, json_body={"secret": "abc"})

    assert len(executor.audit_log) == 1
    log_entry = executor.audit_log[0]

    # Contains metadata only
    assert log_entry["method"] == "POST"
    assert log_entry["url"] == "http://localhost/action"
    assert log_entry["status"] == 200
    assert log_entry["identity"] == "tester"
    assert "latency_ms" in log_entry
    assert "timestamp" in log_entry

    # Contains NO headers or bodies
    assert "headers" not in log_entry
    assert "body" not in log_entry
