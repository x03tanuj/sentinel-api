"""End-to-end integration tests against secure target_api instance (hermetic, no docker).

Guarantees the zero-false-positive promise: a secure target API must produce zero security findings.
"""

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
from app.models import Severity
from app.parser.openapi_loader import load_spec, resolve_and_validate
from app.parser.surface_mapper import build_attack_surface


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_e2e_secure_target_zero_findings(target_servers: dict[str, str]) -> None:
    """Validate that scanning SECURE=true produces ZERO vulnerability findings above INFO."""
    base_url = target_servers["secure_url"]

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

    # Zero security findings for BOLA, BFLA, Unauth Access, Rate Limiting, Data Exposure
    security_checks = {"bola", "bfla", "unauth_access", "rate_limit", "data_exposure"}
    security_findings = [f for f in findings if f.check in security_checks]
    assert len(security_findings) == 0, (
        f"Expected zero security findings on secure target, but found: "
        f"{[(f.check, f.method, f.endpoint, f.title) for f in security_findings]}"
    )

    # Zero findings with severity above INFO
    actionable_findings = [f for f in findings if f.severity != Severity.INFO]
    assert len(actionable_findings) == 0, (
        f"Expected zero findings above INFO on secure target, but found: "
        f"{[(f.severity, f.check, f.endpoint) for f in actionable_findings]}"
    )
