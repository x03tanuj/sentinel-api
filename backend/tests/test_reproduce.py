"""Unit tests for the vulnerability reproduction engine."""

import httpx
import pytest

from app.config import Settings
from app.engine.context import ScanContext
from app.engine.differential import DiffResult
from app.engine.evidence import build_evidence
from app.engine.http_executor import Executor
from app.engine.identity import IdentityManager
from app.engine.reproduce import reproduce_finding, reproduce_top_findings
from app.models import Finding, Identity, RequestRecord, ResponseRecord, Severity


def _make_reproduce_context(transport: httpx.MockTransport) -> ScanContext:
    base_url = "http://localhost:9000"
    executor = Executor(transport=transport)
    mgr = IdentityManager(base_url=base_url, executor=executor)

    user_a = Identity(name="userA", role="user", user_id="1", token="token-a")
    user_b = Identity(name="userB", role="user", user_id="2", token="token-b")
    mgr._identities["userA"] = user_a
    mgr._identities["userB"] = user_b

    return ScanContext(
        base_url=base_url,
        endpoints=[],
        identity_manager=mgr,
        owned={},
        matrix_cells=[],
        cases=[],
        executor=executor,
        settings=Settings(),
    )


def _make_dummy_finding(
    check: str = "bola",
    severity: Severity = Severity.HIGH,
    confidence: float = 0.85,
    status: int = 200,
    identity: str = "userB",
    path: str = "/orders/101",
) -> Finding:
    req = RequestRecord(
        method="GET",
        url=f"http://localhost:9000{path}",
        headers_redacted={"Authorization": "Bearer ***REDACTED***"},
        body=None,
    )
    attack_resp = ResponseRecord(
        status=status,
        headers={},
        body={"id": 101, "customer_id": 1, "items": []},
        size=50,
    )
    diff = DiffResult(
        status_changed=False,
        baseline_status=200,
        attack_status=status,
        body_similarity=0.95,
        schema_similarity=1.0,
        same_object_id=True,
        owner_id_differs=True,
        sensitive_fields_exposed={},
        size_ratio=1.0,
        changed_fields=[],
        attack_body_empty=False,
        attack_body_is_error=False,
    )
    evidence = build_evidence(
        case_result_or_context=None,
        request=req,
        baseline_response=None,
        attack_response=attack_resp,
        diff=diff,
        identity=identity,
        object_id="101",
        expected_status=403,
    )
    return Finding(
        check=check,
        endpoint=path,
        method="GET",
        title=f"Vulnerability on {path}",
        severity=severity,
        confidence=confidence,
        explanation="Test explanation",
        evidence=evidence,
        curl_poc="curl http://localhost:9000" + path,
        fix_hint="Test fix hint",
    )


@pytest.mark.asyncio
async def test_reproduce_finding_success_bumps_confidence() -> None:
    """A finding that reproduces both times gets confidence bump and no downgrade."""
    # Server reproduces the original 200 leak
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 101, "customer_id": 1, "items": []})

    ctx = _make_reproduce_context(httpx.MockTransport(handler))
    finding = _make_dummy_finding(confidence=0.85, severity=Severity.HIGH)

    updated = await reproduce_finding(finding, ctx, attempts=2)

    # 0.85 + 0.05 + 0.03 = 0.93
    assert updated.confidence > 0.85
    assert updated.confidence == 0.93
    assert updated.severity == Severity.HIGH
    assert updated.evidence.response_diff["reproduction"] == {"attempts": 2, "reproduced": 2}
    assert "downgraded" not in updated.evidence.response_diff


@pytest.mark.asyncio
async def test_reproduce_finding_fixed_mid_test_downgraded() -> None:
    """A finding where the mock returns 403 (fixed) gets downgraded by one severity level."""
    # Server now returns 403 Forbidden (patched)
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"detail": "Forbidden"})

    ctx = _make_reproduce_context(httpx.MockTransport(handler))
    finding = _make_dummy_finding(confidence=0.90, severity=Severity.CRITICAL)

    updated = await reproduce_finding(finding, ctx, attempts=2)

    # Severity downgraded: CRITICAL -> HIGH
    assert updated.severity == Severity.HIGH
    assert updated.evidence.response_diff["downgraded"] is True
    assert updated.evidence.response_diff["reproduction"]["reproduced"] == 0
    # Confidence dropped by 0.20
    assert updated.confidence == 0.70


@pytest.mark.asyncio
async def test_reproduce_top_findings_cap_and_notes() -> None:
    """reproduce_top_findings only reproduces top_n and notes skipped findings."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 101, "customer_id": 1})

    ctx = _make_reproduce_context(httpx.MockTransport(handler))

    findings = [
        _make_dummy_finding(severity=Severity.CRITICAL, confidence=0.95, path=f"/orders/{i}")
        for i in range(1, 6)
    ]

    reproduced = await reproduce_top_findings(findings, ctx, top_n=2)

    assert len(reproduced) == 5
    # First 2 must have reproduction metadata
    assert "reproduction" in reproduced[0].evidence.response_diff
    assert "reproduction" in reproduced[1].evidence.response_diff

    # Remaining 3 must NOT have reproduction metadata
    assert "reproduction" not in reproduced[2].evidence.response_diff
    assert "reproduction" not in reproduced[3].evidence.response_diff
    assert "reproduction" not in reproduced[4].evidence.response_diff

    # Notes recorded in ctx
    assert any("reproduction skipped for 3 lower-priority findings" in n for n in ctx.notes)
