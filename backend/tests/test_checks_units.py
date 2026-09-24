"""Unit tests for security checks (MockTransport, finding logic, and execution harness)."""

from typing import Any
import httpx
import pytest

from app.config import Settings
from app.engine.auth_matrix import Outcome
from app.engine.checks.base import BaseCheck, register_check, run_checks
from app.engine.checks.bfla import BflaCheck
from app.engine.checks.bola import BolaCheck
from app.engine.checks.data_exposure import DataExposureCheck
from app.engine.checks.input_handling import InputHandlingCheck
from app.engine.checks.rate_limit import RateLimitCheck
from app.engine.checks.unauth_access import UnauthAccessCheck
from app.engine.context import ScanContext
from app.engine.discovery import OwnedObject
from app.engine.http_executor import Executor
from app.engine.identity import IdentityManager
from app.engine.test_generator import TestCase, TestCategory
from app.models import Endpoint, Finding, Identity, Severity


def _create_context(
    transport: httpx.MockTransport,
    endpoints: list[Endpoint] | None = None,
    settings: Settings | None = None,
) -> ScanContext:
    base_url = "http://localhost:9000"
    cfg = settings or Settings()
    executor = Executor(settings=cfg, transport=transport)
    mgr = IdentityManager(base_url=base_url, executor=executor)

    admin = Identity(name="admin", role="admin", user_id="99", token="tok-admin")
    user_a = Identity(name="userA", role="user", user_id="1", token="tok-a")
    user_b = Identity(name="userB", role="user", user_id="2", token="tok-b")

    mgr._identities["admin"] = admin
    mgr._identities["userA"] = user_a
    mgr._identities["userB"] = user_b

    return ScanContext(
        base_url=base_url,
        endpoints=endpoints or [],
        identity_manager=mgr,
        owned={
            "userA": {"order": [OwnedObject(resource="order", object_id="101", source_endpoint="/orders")]},
            "userB": {"order": [OwnedObject(resource="order", object_id="102", source_endpoint="/orders")]},
        },
        matrix_cells=[],
        cases=[],
        executor=executor,
        settings=cfg,
    )


@pytest.mark.asyncio
async def test_bola_read_finding_and_safe_cases() -> None:
    """BOLA read flags 200 OK leaks with different owner, but ignores 403, 404, soft-fail, and empty bodies."""
    ep = Endpoint(method="GET", path="/orders/{id}", path_params=["id"], resource="order", requires_auth=True)

    # Subtest 1: 200 OK leak of userA order 101 to attacker userB
    def leak_handler(req: httpx.Request) -> httpx.Response:
        auth = req.headers.get("authorization", "")
        if "tok-a" in auth:
            return httpx.Response(200, json={"id": 101, "owner_id": 1, "item": "book"})
        elif "tok-b" in auth:
            return httpx.Response(200, json={"id": 101, "owner_id": 1, "item": "book"})
        return httpx.Response(404)

    ctx1 = _create_context(httpx.MockTransport(leak_handler), [ep])
    ctx1.cases = [
        TestCase(
            category=TestCategory.CROSS_USER,
            endpoint=ep,
            identity_name="userB",
            owner_identity="userA",
            object_id="101",
            expected_outcome=Outcome.DENY,
        )
    ]
    findings1 = await BolaCheck().run(ctx1)
    assert len(findings1) == 1
    assert findings1[0].check == "bola"
    assert findings1[0].severity == Severity.HIGH
    assert findings1[0].confidence >= 0.85

    # Subtest 2: Safe responses (403, 404, soft-fail 200, empty 200)
    for safe_status, safe_body in [
        (403, {"detail": "Forbidden"}),
        (404, {"detail": "Not found"}),
        (200, {"error": "Unauthorized access", "detail": "Access denied"}),
        (200, {}),
    ]:
        def safe_handler(req: httpx.Request, st=safe_status, b=safe_body) -> httpx.Response:
            auth = req.headers.get("authorization", "")
            if "tok-a" in auth:
                return httpx.Response(200, json={"id": 101, "owner_id": 1})
            return httpx.Response(st, json=b)

        ctx_safe = _create_context(httpx.MockTransport(safe_handler), [ep])
        ctx_safe.cases = [
            TestCase(
                category=TestCategory.CROSS_USER,
                endpoint=ep,
                identity_name="userB",
                owner_identity="userA",
                object_id="101",
                expected_outcome=Outcome.DENY,
            )
        ]
        findings_safe = await BolaCheck().run(ctx_safe)
        assert len(findings_safe) == 0, f"Expected no finding for status {safe_status} with body {safe_body}"


@pytest.mark.asyncio
async def test_bfla_finding_vs_403() -> None:
    """BFLA detects privileged routes accessed by non-admin identities and stays quiet on 403."""
    ep_admin = Endpoint(
        method="GET",
        path="/admin/users",
        requires_auth=True,
        is_privileged=True,
    )

    # Vulnerable target returns 200 to userA
    def vuln_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"id": 1, "username": "admin"}, {"id": 2, "username": "userA"}])

    ctx_vuln = _create_context(httpx.MockTransport(vuln_handler), [ep_admin])
    findings_vuln = await BflaCheck().run(ctx_vuln)
    assert len(findings_vuln) >= 1
    assert any(f.check == "bfla" for f in findings_vuln)

    # Secure target returns 403 to userA and userB, 200 to admin
    def secure_handler(req: httpx.Request) -> httpx.Response:
        auth = req.headers.get("authorization", "")
        if "tok-admin" in auth:
            return httpx.Response(200, json=[{"id": 1}])
        return httpx.Response(403, json={"detail": "Admin required"})

    ctx_secure = _create_context(httpx.MockTransport(secure_handler), [ep_admin])
    findings_secure = await BflaCheck().run(ctx_secure)
    assert len(findings_secure) == 0


@pytest.mark.asyncio
async def test_unauth_finding_vs_401() -> None:
    """Unauthenticated access check flags 200 OK on auth-required endpoints and passes on 401."""
    ep = Endpoint(method="GET", path="/reports/summary", requires_auth=True)

    # Vulnerable returns 200
    def vuln_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"total_sales": 1000, "metrics": [1, 2, 3]})

    ctx_vuln = _create_context(httpx.MockTransport(vuln_handler), [ep])
    findings_vuln = await UnauthAccessCheck().run(ctx_vuln)
    assert len(findings_vuln) == 1
    assert findings_vuln[0].check == "unauth_access"

    # Secure returns 401
    def secure_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "Not authenticated"})

    ctx_secure = _create_context(httpx.MockTransport(secure_handler), [ep])
    findings_secure = await UnauthAccessCheck().run(ctx_secure)
    assert len(findings_secure) == 0


@pytest.mark.asyncio
async def test_rate_limit_probe_and_detection() -> None:
    """Rate limit check flags endpoints without 429 and acknowledges rate limiting when 429 occurs."""
    ep = Endpoint(method="POST", path="/auth/login", requires_auth=False)

    # Scenario 1: 40 x 401 with no 429
    def unthrottled_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "Invalid credentials"})

    ctx_unthrottled = _create_context(
        httpx.MockTransport(unthrottled_handler),
        [ep],
        settings=Settings(RATE_LIMIT_PROBE_COUNT=40),
    )
    findings = await RateLimitCheck().run(ctx_unthrottled)
    assert len(findings) == 1
    assert findings[0].check == "rate_limit"

    # Scenario 2: 429 returned after 10 requests
    req_counter = 0

    def throttled_handler(req: httpx.Request) -> httpx.Response:
        nonlocal req_counter
        req_counter += 1
        if req_counter >= 11:
            return httpx.Response(429, json={"detail": "Too many requests"}, headers={"Retry-After": "60"})
        return httpx.Response(401, json={"detail": "Invalid credentials"})

    ctx_throttled = _create_context(
        httpx.MockTransport(throttled_handler),
        [ep],
        settings=Settings(RATE_LIMIT_PROBE_COUNT=40),
    )
    findings_throttled = await RateLimitCheck().run(ctx_throttled)
    assert len(findings_throttled) == 0
    noted = [n for n in ctx_throttled.notes if "rate limiting observed on /auth/login after 11 requests" in n]
    assert len(noted) == 1


@pytest.mark.asyncio
async def test_data_exposure_undeclared_vs_declared() -> None:
    """Data exposure flags undeclared sensitive fields and ignores declared-only and admin responses."""
    schema = {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "username": {"type": "string"},
            "email": {"type": "string"},
        },
    }
    ep = Endpoint(
        method="GET",
        path="/users/{id}",
        path_params=["id"],
        resource="user",
        requires_auth=True,
        response_schema=schema,
    )

    # Case 1: Leaks ssn (undeclared SECRET) and password_hash
    def leak_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": 1,
                "username": "userA",
                "email": "a@test.com",
                "ssn": "444-55-6666",
                "password_hash": "hash123",
            },
        )

    ctx_leak = _create_context(httpx.MockTransport(leak_handler), [ep])
    findings_leak = await DataExposureCheck().run(ctx_leak)
    assert len(findings_leak) >= 1
    assert any(f.check == "data_exposure" and "ssn" in f.explanation for f in findings_leak)

    # Case 2: Only declared fields returned
    def clean_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "username": "userA", "email": "a@test.com"})

    ctx_clean = _create_context(httpx.MockTransport(clean_handler), [ep])
    findings_clean = await DataExposureCheck().run(ctx_clean)
    assert len(findings_clean) == 0


@pytest.mark.asyncio
async def test_input_handling_500_info() -> None:
    """Input handling flags 500 errors on malformed boundary IDs as INFO."""
    ep = Endpoint(method="GET", path="/orders/{id}", path_params=["id"], resource="order", requires_auth=True)

    def crash_handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"detail": "Database crash on invalid integer"})

    ctx = _create_context(httpx.MockTransport(crash_handler), [ep])
    ctx.cases = [
        TestCase(
            category=TestCategory.BOUNDARY,
            endpoint=ep,
            identity_name="userA",
            object_id="0",
            expected_outcome=Outcome.DENY,
        )
    ]

    findings = await InputHandlingCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].check == "input_handling"
    assert findings[0].severity == Severity.INFO
    assert findings[0].confidence == 0.70


@pytest.mark.asyncio
async def test_run_checks_error_isolation_threshold_and_deduplication() -> None:
    """run_checks isolates check crashes, filters below MIN_REPORT_CONFIDENCE, and aggregates duplicate findings."""
    class FailingCheck(BaseCheck):
        name: str = "failing_check"
        owasp_id: str = "API10:2023"
        description: str = "Throws exception"

        async def run(self, ctx: ScanContext) -> list[Finding]:
            raise RuntimeError("Database connection exploded")

    class LowConfCheck(BaseCheck):
        name: str = "low_conf_check"
        owasp_id: str = "API1:2023"
        description: str = "Generates low confidence finding"

        async def run(self, ctx: ScanContext) -> list[Finding]:
            ep = Endpoint(method="GET", path="/test", requires_auth=False)
            return [
                Finding(
                    check=self.name,
                    endpoint="/test",
                    method="GET",
                    title="Low confidence",
                    severity=Severity.LOW,
                    confidence=0.30,  # Below default 0.50
                    explanation="Not sure",
                    curl_poc="curl http://test",
                    fix_hint="None",
                )
            ]

    class DuplicateCheck(BaseCheck):
        name: str = "dup_check"
        owasp_id: str = "API1:2023"
        description: str = "Generates duplicates across object IDs"

        async def run(self, ctx: ScanContext) -> list[Finding]:
            from app.models import Evidence, RequestRecord, ResponseRecord
            req = RequestRecord(method="GET", url="http://localhost:9000/orders/101", headers={})
            resp = ResponseRecord(status=200, headers={}, body={"id": 101}, size=10, latency_ms=1.0)
            f1 = Finding(
                check=self.name,
                endpoint="/orders/{id}",
                method="GET",
                title="BOLA on order",
                severity=Severity.HIGH,
                confidence=0.85,
                explanation="IDOR",
                evidence=Evidence(identity="userB", object_id="101", actual_status=200, request=req, attack_response=resp),
                curl_poc="curl ...",
                fix_hint="Fix",
            )
            f2 = Finding(
                check=self.name,
                endpoint="/orders/{id}",
                method="GET",
                title="BOLA on order",
                severity=Severity.HIGH,
                confidence=0.90,  # Stronger confidence
                explanation="IDOR",
                evidence=Evidence(identity="userB", object_id="102", actual_status=200, request=req, attack_response=resp),
                curl_poc="curl ...",
                fix_hint="Fix",
            )
            return [f1, f2]

    try:
        register_check(FailingCheck())
        register_check(LowConfCheck())
        register_check(DuplicateCheck())

        ctx = _create_context(httpx.MockTransport(lambda req: httpx.Response(200)))
        findings = await run_checks(ctx, enabled=["failing_check", "low_conf_check", "dup_check"])

        # 1. Failing check didn't crash scan; error was logged in notes
        check_errs = [n for n in ctx.notes if "check_error:failing_check:RuntimeError" in n]
        assert len(check_errs) == 1

        # 2. Low confidence finding was dropped and noted
        dropped_notes = [n for n in ctx.notes if "findings dropped below confidence threshold" in n]
        assert len(dropped_notes) == 1

        # 3. Duplicate findings on (dup_check, GET, /orders/{id}, userB) aggregated into 1
        assert len(findings) == 1
        agg = findings[0]
        assert agg.confidence == 0.90
        assert agg.evidence is not None
        assert "affected_objects" in agg.evidence.response_diff
        assert "101" in agg.evidence.response_diff["affected_objects"]
        assert "102" in agg.evidence.response_diff["affected_objects"]
    finally:
        from app.engine.checks.base import CHECKS
        CHECKS.pop("failing_check", None)
        CHECKS.pop("low_conf_check", None)
        CHECKS.pop("dup_check", None)
