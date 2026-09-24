"""Unit and integration tests for FastAPI REST routes, SSE events, and security filters."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import pytest
import httpx

from app.config import Settings
from app.engine.scanner import ScanConfig, ScanResult
from app.main import create_app
from app.scan_manager import ScanManager


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    return Settings(
        DATA_DIR=str(tmp_path),
        ALLOWED_HOSTS=["127.0.0.1", "localhost"],
        SENTINEL_API_KEY=None,
        CORS_ORIGINS=["http://localhost:5173"],
        MAX_CONCURRENT_SCANS=2,
    )


@pytest.fixture
async def client_and_app(test_settings: Settings):
    app = create_app(test_settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client, app


def _valid_scan_payload(base_url: str = "http://127.0.0.1:9000", password: str = "SecretPass123!") -> dict:
    return {
        "spec_inline": {"openapi": "3.0.0", "paths": {}},
        "base_url": base_url,
        "identities": [
            {
                "name": "tester",
                "role": "user",
                "username": "test_user",
                "password": password,
                "login_path": "/auth/login",
            }
        ],
        "test_case_budget": 50,
        "max_requests": 100,
    }


@pytest.mark.asyncio
async def test_route_post_scan_202_flow(client_and_app) -> None:
    """POST /scans accepts job, returns 202 with status and events URLs."""
    client, app = client_and_app

    # Inject dummy runner so scan completes quickly
    async def fake_runner(cfg, on_progress, settings, scan_id):
        return ScanResult(findings=[], summary={"total_findings": 0, "by_severity": {}})

    app.state.scan_manager.runner = fake_runner

    resp = await client.post("/scans", json=_valid_scan_payload())
    assert resp.status_code == 202
    data = resp.json()

    assert "scan_id" in data
    assert data["status"] in ("queued", "running")
    assert data["status_url"] == f"/scans/{data['scan_id']}"
    assert data["events_url"] == f"/scans/{data['scan_id']}/events"


@pytest.mark.asyncio
async def test_route_out_of_scope_400_no_credential_echo(client_and_app) -> None:
    """Out-of-scope targets return 400 Bad Request without echoing credentials."""
    client, app = client_and_app
    sensitive_pass = "P@sswordNeverEchoMe999!"

    payload = _valid_scan_payload(base_url="http://unauthorized-domain.com", password=sensitive_pass)
    resp = await client.post("/scans", json=payload)

    assert resp.status_code == 400
    assert "out of authorized scope" in resp.text
    # Credential must NOT be echoed back
    assert sensitive_pass not in resp.text


@pytest.mark.asyncio
async def test_route_invalid_body_422_no_password_echo(client_and_app) -> None:
    """Invalid JSON schema returns 422 Unprocessable Entity without echoing passwords."""
    client, app = client_and_app
    sensitive_pass = "SecretShouldNotBeIn422Response!"

    # Send missing required base_url but include sensitive password
    payload = {
        "spec_inline": {"openapi": "3.0.0", "paths": {}},
        "identities": [
            {
                "name": "tester",
                "role": "user",
                "username": "user",
                "password": sensitive_pass,
                "login_path": "/auth/login",
            }
        ],
    }
    resp = await client.post("/scans", json=payload)
    assert resp.status_code == 422
    assert sensitive_pass not in resp.text


@pytest.mark.asyncio
async def test_route_get_list_and_detail(client_and_app) -> None:
    """GET /scans and GET /scans/{id} return expected metadata."""
    client, app = client_and_app
    store = app.state.store

    rec = await store.create({"base_url": "http://127.0.0.1:9000", "tag": "test"})

    # List
    list_resp = await client.get("/scans?limit=10&offset=0")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert len(items) >= 1
    assert items[0]["id"] == rec.id

    # Detail
    detail_resp = await client.get(f"/scans/{rec.id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == rec.id
    assert detail["status"] == "queued"
    assert detail["config_public"]["base_url"] == "http://127.0.0.1:9000"


@pytest.mark.asyncio
async def test_route_findings_filters_and_validation(client_and_app) -> None:
    """GET /scans/{id}/findings supports severity, check, confidence filters, and validation."""
    client, app = client_and_app
    store = app.state.store

    # Seed completed scan with diverse findings
    rec = await store.create({"base_url": "http://127.0.0.1:9000"})
    result = ScanResult(
        findings=[
            {"id": "f1", "check": "bola", "severity": "CRITICAL", "confidence": 0.95, "endpoint": "/orders/1", "method": "GET"},
            {"id": "f2", "check": "bfla", "severity": "HIGH", "confidence": 0.85, "endpoint": "/admin/users", "method": "POST"},
            {"id": "f3", "check": "data_exposure", "severity": "MEDIUM", "confidence": 0.60, "endpoint": "/profile", "method": "GET"},
        ],
        surface=[{"endpoint": "/orders/1", "score": 90}],
        matrix={"identities": ["u1"], "cells": []},
        matrix_summary={"total_cells": 1},
        notes=["Telemetry note"],
        summary={"total_findings": 3, "by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 0}},
    )
    await store.save_result(rec.id, result)

    # 1. Filter by severity
    resp_crit = await client.get(f"/scans/{rec.id}/findings?severity=CRITICAL")
    assert resp_crit.status_code == 200
    data_crit = resp_crit.json()
    assert data_crit["total"] == 1
    assert data_crit["findings"][0]["id"] == "f1"

    # 2. Filter by check
    resp_check = await client.get(f"/scans/{rec.id}/findings?check=bfla")
    assert resp_check.status_code == 200
    data_check = resp_check.json()
    assert data_check["total"] == 1
    assert data_check["findings"][0]["id"] == "f2"

    # 3. Filter by min_confidence
    resp_conf = await client.get(f"/scans/{rec.id}/findings?min_confidence=0.80")
    assert resp_conf.status_code == 200
    assert resp_conf.json()["total"] == 2

    # 4. Invalid filters -> 422
    assert (await client.get(f"/scans/{rec.id}/findings?severity=INVALID")).status_code == 422
    assert (await client.get(f"/scans/{rec.id}/findings?check=invalid_check_name")).status_code == 422
    assert (await client.get(f"/scans/{rec.id}/findings?min_confidence=1.5")).status_code == 422
    assert (await client.get(f"/scans/{rec.id}/findings?sort=invalid_sort")).status_code == 422
    assert (await client.get(f"/scans/{rec.id}/findings?order=sideways")).status_code == 422

    # 5. Single finding by ID
    resp_single = await client.get(f"/scans/{rec.id}/findings/f1")
    assert resp_single.status_code == 200
    assert resp_single.json()["id"] == "f1"

    # Unknown finding ID -> 404
    assert (await client.get(f"/scans/{rec.id}/findings/unknown_999")).status_code == 404


@pytest.mark.asyncio
async def test_route_unknown_ids_404(client_and_app) -> None:
    """Requests for nonexistent scan IDs return 404 Not Found."""
    client, _ = client_and_app
    fake_id = "00000000-0000-0000-0000-000000000000"

    assert (await client.get(f"/scans/{fake_id}")).status_code == 404
    assert (await client.get(f"/scans/{fake_id}/findings")).status_code == 404
    assert (await client.get(f"/scans/{fake_id}/surface")).status_code == 404
    assert (await client.get(f"/scans/{fake_id}/matrix")).status_code == 404
    assert (await client.get(f"/scans/{fake_id}/notes")).status_code == 404
    assert (await client.get(f"/scans/{fake_id}/events")).status_code == 404
    assert (await client.get(f"/scans/{fake_id}/report.json")).status_code == 404
    assert (await client.get(f"/scans/{fake_id}/report.md")).status_code == 404


@pytest.mark.asyncio
async def test_route_unfinished_scan_returns_409(client_and_app) -> None:
    """Result-bearing endpoints return 409 Conflict if scan is not yet completed."""
    client, app = client_and_app
    store = app.state.store

    rec = await store.create({"base_url": "http://127.0.0.1:9000"})
    await store.update_status(rec.id, "running")

    # Result routes return 409
    assert (await client.get(f"/scans/{rec.id}/findings")).status_code == 409
    assert (await client.get(f"/scans/{rec.id}/findings/f1")).status_code == 409
    assert (await client.get(f"/scans/{rec.id}/surface")).status_code == 409
    assert (await client.get(f"/scans/{rec.id}/matrix")).status_code == 409
    assert (await client.get(f"/scans/{rec.id}/notes")).status_code == 409
    assert (await client.get(f"/scans/{rec.id}/report.json")).status_code == 409
    assert (await client.get(f"/scans/{rec.id}/report.md")).status_code == 409


@pytest.mark.asyncio
async def test_route_sse_events_streaming(client_and_app) -> None:
    """GET /scans/{id}/events returns text/event-stream with progress events.

    Note: ASGITransport buffers streaming responses in tests until closed,
    so we test against a scan that has completed its event emissions.
    """
    client, app = client_and_app
    store = app.state.store

    rec = await store.create({"base_url": "http://127.0.0.1:9000"})
    event1 = {"seq": 1, "scan_id": rec.id, "stage": "loading_spec", "status": "running", "percent": 5, "message": "Loading"}
    event2 = {"seq": 2, "scan_id": rec.id, "stage": "finalizing", "status": "completed", "percent": 100, "message": "Done"}
    await store.append_event(rec.id, event1)
    await store.append_event(rec.id, event2)
    await store.update_status(rec.id, "completed")

    resp = await client.get(f"/scans/{rec.id}/events")
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]
    assert resp.headers["cache-control"] == "no-cache"
    assert resp.headers["x-accel-buffering"] == "no"

    body = resp.text
    assert "event: progress\n" in body
    assert '"percent": 5' in body
    assert '"percent": 100' in body


@pytest.mark.asyncio
async def test_route_cancel_and_delete_rules(client_and_app) -> None:
    """Cancellation and deletion state transition rules."""
    client, app = client_and_app
    store = app.state.store

    # 1. Create a running scan
    rec = await store.create({"base_url": "http://127.0.0.1:9000"})
    await store.update_status(rec.id, "running")

    # Cannot delete running scan -> 409
    del_resp = await client.delete(f"/scans/{rec.id}")
    assert del_resp.status_code == 409

    # Cancel scan -> 200
    cancel_resp = await client.post(f"/scans/{rec.id}/cancel")
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["cancelled"] is True

    # Cancel already cancelled/finished scan -> 409
    cancel_second = await client.post(f"/scans/{rec.id}/cancel")
    assert cancel_second.status_code == 409

    # Delete finished scan -> 204
    del_ok = await client.delete(f"/scans/{rec.id}")
    assert del_ok.status_code == 204

    # Delete again -> 404
    del_404 = await client.delete(f"/scans/{rec.id}")
    assert del_404.status_code == 404


@pytest.mark.asyncio
async def test_route_api_key_authentication(tmp_path: Path) -> None:
    """When SENTINEL_API_KEY is configured, /scans requires valid X-API-Key."""
    settings = Settings(
        DATA_DIR=str(tmp_path),
        ALLOWED_HOSTS=["127.0.0.1", "localhost"],
        SENTINEL_API_KEY="super-secret-api-key-xyz",
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # /health and /scope stay open
            assert (await client.get("/health")).status_code == 200
            assert (await client.get("/scope")).status_code == 200

            # /scans without key -> 401
            assert (await client.get("/scans")).status_code == 401

            # /scans with invalid key -> 401
            assert (await client.get("/scans", headers={"X-API-Key": "wrong-key"})).status_code == 401

            # /scans with valid key -> 200
            assert (await client.get("/scans", headers={"X-API-Key": "super-secret-api-key-xyz"})).status_code == 200


@pytest.mark.asyncio
async def test_route_cors_and_openapi_operation_ids(client_and_app) -> None:
    """CORS origins are respected and all routes define explicit operationId."""
    client, app = client_and_app

    # Allowed origin CORS check
    resp_cors = await client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert resp_cors.headers.get("access-control-allow-origin") == "http://localhost:5173"

    # OpenAPI schema verification
    openapi = app.openapi()
    paths = openapi.get("paths", {})

    for path, methods in paths.items():
        for method, op in methods.items():
            if method.lower() in ("get", "post", "put", "delete", "patch"):
                op_id = op.get("operationId")
                assert op_id is not None, f"Route {method.upper()} {path} is missing operationId"
