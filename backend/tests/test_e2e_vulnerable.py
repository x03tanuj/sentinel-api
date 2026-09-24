"""End-to-end integration tests against vulnerable target_api instance (hermetic, no docker)."""

import json
from pathlib import Path
from typing import Any

import httpx
from pydantic import SecretStr
import pytest

from app.config import Settings
from app.engine.auth_matrix import build_matrix
from app.engine.checks import run_checks
from app.engine.context import ScanContext
from app.engine.discovery import discover_ownership
from app.engine.http_executor import Executor
from app.engine.identity import IdentityConfig, IdentityManager
from app.engine.test_generator import generate_all
from app.parser.openapi_loader import load_spec, resolve_and_validate
from app.parser.surface_mapper import build_attack_surface

SEED_SSNS = ["111-22-3333", "444-55-6666", "777-88-9999"]


async def _run_full_scan_pipeline(base_url: str) -> tuple[ScanContext, list[Any]]:
    """Helper to run the full scan pipeline against a running target server."""
    # Reset target database before scanning
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{base_url}/_reset", timeout=5.0)
        assert resp.status_code == 200

    spec_url = f"{base_url}/openapi.json"
    raw_spec = await load_spec(spec_url)
    resolved_spec = resolve_and_validate(raw_spec)
    endpoints = build_attack_surface(resolved_spec)

    cfg = Settings(
        ALLOWED_HOSTS=["localhost", "127.0.0.1"],
        MAX_RPS=30,
        RATE_LIMIT_PROBE_COUNT=25,
        CHECK_TIMEOUT_SECONDS=30,
    )
    executor = Executor(settings=cfg)

    mgr = IdentityManager(base_url=base_url, executor=executor)
    configs = [
        IdentityConfig(name="userA", role="user", username="userA", password=SecretStr("passA123")),
        IdentityConfig(name="userB", role="user", username="userB", password=SecretStr("passB123")),
        IdentityConfig(name="admin", role="admin", username="admin", password=SecretStr("admin123")),
    ]
    identities = await mgr.login_all(configs)

    owned = await discover_ownership(endpoints, identities, executor, base_url=base_url)
    matrix_cells = build_matrix(owned, identities)
    test_res = generate_all(endpoints, identities, owned, matrix_cells, budget=150)

    sample_bodies = {
        "order": {
            "items": [{"product_id": 1, "qty": 1}],
            "shipping_address": "SentinelAPI test",
        }
    }

    ctx = ScanContext(
        base_url=base_url,
        endpoints=endpoints,
        identity_manager=mgr,
        owned=owned,
        matrix_cells=matrix_cells,
        cases=test_res.cases,
        executor=executor,
        settings=cfg,
        sample_bodies=sample_bodies,
    )

    findings = await run_checks(ctx)
    await executor.aclose()
    return ctx, findings


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_e2e_vulnerable_target_findings(target_servers: dict[str, str]) -> None:
    """Validate that the scan pipeline against SECURE=false identifies all expected vulnerabilities."""
    base_url = target_servers["vulnerable_url"]
    ctx, findings = await _run_full_scan_pipeline(base_url)

    # 1. Assert required vulnerability types are present
    finding_keys = {(f.check, f.method, f.endpoint) for f in findings}

    # BOLA Read
    bola_reads = [f for f in findings if f.check == "bola" and f.method == "GET" and "/orders" in f.endpoint]
    assert len(bola_reads) >= 1, "Missing BOLA read finding on GET /orders/{id}"

    # BOLA Write (PUT and/or DELETE on orders)
    bola_writes = [f for f in findings if f.check == "bola" and f.method in ("PUT", "DELETE")]
    assert len(bola_writes) >= 1, "Missing BOLA write finding on PUT/DELETE /orders/{id}"

    # BFLA
    bfla_findings = [f for f in findings if f.check == "bfla" and "/admin" in f.endpoint]
    assert len(bfla_findings) >= 1, "Missing BFLA finding on GET /admin/users"

    # Excessive Data Exposure
    exposure_findings = [f for f in findings if f.check == "data_exposure" and "/users" in f.endpoint]
    assert len(exposure_findings) >= 1, "Missing Data Exposure finding on GET /users/{id}"

    # Unauthenticated Access
    unauth_findings = [f for f in findings if f.check == "unauth_access" and "/reports" in f.endpoint]
    assert len(unauth_findings) >= 1, "Missing Unauth Access finding on GET /reports/summary"

    # Rate Limiting
    rate_findings = [f for f in findings if f.check == "rate_limit" and "/auth" in f.endpoint]
    assert len(rate_findings) >= 1, "Missing Rate Limit finding on POST /auth/login"

    # 2. Assert evidence, curl_poc, and redaction compliance on every finding
    serialized_findings = json.dumps([f.to_dict() for f in findings])

    for f in findings:
        assert f.evidence is not None, f"Finding {f.title} lacks evidence artifact"
        assert f.confidence >= ctx.settings.MIN_REPORT_CONFIDENCE
        # curl_poc uses $TOKEN or no token, never raw JWT
        assert "eyJ" not in f.curl_poc
        if "Authorization" in f.curl_poc:
            assert "$TOKEN" in f.curl_poc or "-H 'Authorization: Bearer $TOKEN'" in f.curl_poc

    # No raw tokens or SSNs anywhere in serialized output
    assert "Bearer eyJ" not in serialized_findings
    for ssn in SEED_SSNS:
        assert ssn not in serialized_findings

    # 3. Assert cleanup left no scanner-created orders behind and seed order 104 exists
    async with httpx.AsyncClient() as client:
        # Login as userA to inspect order collection
        r_login_a = await client.post(
            f"{base_url}/auth/login",
            json={"username": "userA", "password": "passA123"},
        )
        token_a = r_login_a.json()["access_token"]

        # Check seed order 104 still exists (accessible to admin or owner userB)
        r_login_b = await client.post(
            f"{base_url}/auth/login",
            json={"username": "userB", "password": "passB123"},
        )
        token_b = r_login_b.json()["access_token"]
        r_104 = await client.get(
            f"{base_url}/orders/104",
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert r_104.status_code == 200
        r_orders_a = await client.get(
            f"{base_url}/orders",
            headers={"Authorization": f"Bearer {token_a}"},
        )
        user_a_order_ids = [str(o["id"]) for o in r_orders_a.json()]
        # UserA seed orders are 101, 102, 103
        for oid in user_a_order_ids:
            assert oid in ("101", "102", "103"), f"Unexpected leftover order {oid} for userA"


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_precision_determinism(target_servers: dict[str, str]) -> None:
    """Validate that identical scan runs produce deterministic findings."""
    base_url = target_servers["vulnerable_url"]

    _, findings_run1 = await _run_full_scan_pipeline(base_url)
    _, findings_run2 = await _run_full_scan_pipeline(base_url)

    keys1 = {
        (f.check, f.method, f.endpoint, f.evidence.identity if f.evidence else "")
        for f in findings_run1
    }
    keys2 = {
        (f.check, f.method, f.endpoint, f.evidence.identity if f.evidence else "")
        for f in findings_run2
    }

    assert keys1 == keys2, f"Discrepancy between consecutive scan runs: {keys1.symmetric_difference(keys2)}"
