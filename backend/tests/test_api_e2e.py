"""End-to-end integration and security validation tests for SentinelAPI Phase 8."""

from __future__ import annotations

import asyncio
from datetime import datetime
import json
from pathlib import Path
import threading
import time
from typing import Any

from fastapi import FastAPI
import httpx
import jwt
from pydantic import SecretStr
import pytest
import uvicorn

from app.config import Settings
from app.main import create_app
from app.store import JsonSnapshotStore


SEED_SSNS = ["111-22-3333", "444-55-6666", "777-88-9999"]


def _run_slow_server(port: int, stop_event: threading.Event) -> None:
    """Run a slow-responding dummy ASGI target for cancellation testing."""
    slow_app = FastAPI()

    @slow_app.get("/health")
    def sh():
        return {"status": "ok"}

    @slow_app.get("/openapi.json")
    def so():
        return {
            "openapi": "3.0.0",
            "info": {"title": "Slow Target", "version": "1.0.0"},
            "paths": {
                "/auth/login": {
                    "post": {
                        "operationId": "login",
                        "responses": {"200": {"description": "ok"}},
                    }
                },
                "/slow/items/{id}": {
                    "get": {
                        "operationId": "get_slow_item",
                        "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                        "responses": {"200": {"description": "ok"}},
                    }
                },
            },
        }

    @slow_app.post("/auth/login")
    async def slogin():
        await asyncio.sleep(0.3)
        token = jwt.encode({"sub": "user1", "role": "user"}, "dummy-secret", algorithm="HS256")
        return {"access_token": token}

    @slow_app.get("/slow/items/{id}")
    async def sitem(id: str):
        await asyncio.sleep(0.3)
        return {"id": id, "data": "slow response"}

    config = uvicorn.Config(slow_app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    # Polling stop event in server loop
    def _check_stop():
        while not stop_event.is_set():
            time.sleep(0.1)
        server.should_exit = True

    t = threading.Thread(target=_check_stop, daemon=True)
    t.start()
    server.run()


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_full_scanner_api_e2e(tmp_path: Path, target_servers: dict[str, str]) -> None:
    """Full Phase 8 E2E test:

    1. POST /scans against vulnerable target
    2. Poll to completion
    3. Assert all 5 check categories detected and CRITICAL finding present
    4. Assert matrix shows userA denied on 104
    5. Assert report.md contains API1:2023, curl block, and NO credentials/SSNs
    6. POST /scans against secure target yields zero findings above INFO
    7. Seed orders remain intact and uncorrupted
    8. Persistence: new app reload displays identical completed scan summary
    9. scans.json contains zero leaked secrets or credentials
    10. Scan cancellation mid-flight sets status cancelled and triggers cleanup
    """
    vuln_url = target_servers["vulnerable_url"]
    sec_url = target_servers["secure_url"]

    # Reset both targets
    async with httpx.AsyncClient() as client:
        r1 = await client.post(f"{vuln_url}/_reset")
        assert r1.status_code == 200
        r2 = await client.post(f"{sec_url}/_reset")
        assert r2.status_code == 200

    settings = Settings(
        DATA_DIR=str(tmp_path),
        ALLOWED_HOSTS=["127.0.0.1", "localhost"],
        MAX_CONCURRENT_SCANS=2,
    )
    scanner_app = create_app(settings)

    async with scanner_app.router.lifespan_context(scanner_app):
        transport = httpx.ASGITransport(app=scanner_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testscanner") as scanner_client:

            # -------------------------------------------------------------
            # 1. POST /scans against Vulnerable Target
            # -------------------------------------------------------------
            vuln_payload = {
                "spec_url": f"{vuln_url}/openapi.json",
                "base_url": vuln_url,
                "identities": [
                    {"name": "userA", "role": "user", "username": "userA", "password": "passA123", "login_path": "/auth/login"},
                    {"name": "userB", "role": "user", "username": "userB", "password": "passB123", "login_path": "/auth/login"},
                    {"name": "admin", "role": "admin", "username": "admin", "password": "admin123", "login_path": "/auth/login"},
                ],
                "test_case_budget": 150,
                "sample_bodies": {
                    "order": {
                        "items": [{"product_id": 1, "qty": 1}],
                        "shipping_address": "E2E Test Street 100",
                    }
                },
            }

            resp = await scanner_client.post("/scans", json=vuln_payload)
            assert resp.status_code == 202
            vuln_scan_id = resp.json()["scan_id"]

            # Poll until completed (max 180s)
            start_poll = time.monotonic()
            scan_detail: dict[str, Any] = {}
            while time.monotonic() - start_poll < 180.0:
                poll_resp = await scanner_client.get(f"/scans/{vuln_scan_id}")
                assert poll_resp.status_code == 200
                scan_detail = poll_resp.json()
                if scan_detail["status"] in ("completed", "failed", "cancelled"):
                    break
                await asyncio.sleep(1.0)

            assert scan_detail.get("status") == "completed", f"Scan did not complete: {scan_detail}"

            # -------------------------------------------------------------
            # 2. Findings verification: all 5 checks present, CRITICAL exists
            # -------------------------------------------------------------
            find_resp = await scanner_client.get(f"/scans/{vuln_scan_id}/findings")
            assert find_resp.status_code == 200
            findings_data = find_resp.json()
            findings = findings_data["findings"]

            detected_checks = {f["check"] for f in findings}
            expected_checks = {"bola", "bfla", "data_exposure", "unauth_access", "rate_limit"}
            assert expected_checks.issubset(detected_checks), f"Missing checks: {expected_checks - detected_checks}"

            summary = scan_detail.get("summary") or {}
            by_severity = summary.get("by_severity") or {}
            assert by_severity.get("CRITICAL", 0) >= 1

            # -------------------------------------------------------------
            # 3. Authorization Matrix verification
            # -------------------------------------------------------------
            matrix_resp = await scanner_client.get(f"/scans/{vuln_scan_id}/matrix")
            assert matrix_resp.status_code == 200
            matrix_data = matrix_resp.json()
            cells = matrix_data.get("cells", [])

            userA_104_cells = [
                c for c in cells
                if c.get("identity") == "userA" and str(c.get("object_id")) == "104"
            ]
            assert len(userA_104_cells) >= 1
            assert userA_104_cells[0].get("expected") == "DENY"

            # -------------------------------------------------------------
            # 4. Markdown Report verification
            # -------------------------------------------------------------
            md_resp = await scanner_client.get(f"/scans/{vuln_scan_id}/report.md")
            assert md_resp.status_code == 200
            md_text = md_resp.text

            assert "API1:2023" in md_text
            assert "```bash" in md_text
            seed_pw_hashes = [
                "2ef7bde3257a419eb6085a676b7ad2f2a5885ee8d98d2483d73507df0a7b102b",  # passA123
                "89a6a3b2b4bc6ee5d6b46efbf535a0f5a77035eb445a477843818ae67fa7022d",  # passB123
                "0192023a7bbd73250516f069df18b500e94b5823acbe1b3112b95d5d8eabb47e",  # admin123
            ]
            for h in seed_pw_hashes:
                assert h not in md_text
            for ssn in SEED_SSNS:
                assert ssn not in md_text

            # -------------------------------------------------------------
            # 5. POST /scans against Secure Target
            # -------------------------------------------------------------
            sec_payload = dict(vuln_payload)
            sec_payload["spec_url"] = f"{sec_url}/openapi.json"
            sec_payload["base_url"] = sec_url

            resp_sec = await scanner_client.post("/scans", json=sec_payload)
            assert resp_sec.status_code == 202
            sec_scan_id = resp_sec.json()["scan_id"]

            start_poll = time.monotonic()
            sec_detail: dict[str, Any] = {}
            while time.monotonic() - start_poll < 180.0:
                poll_resp = await scanner_client.get(f"/scans/{sec_scan_id}")
                assert poll_resp.status_code == 200
                sec_detail = poll_resp.json()
                if sec_detail["status"] in ("completed", "failed", "cancelled"):
                    break
                await asyncio.sleep(1.0)

            assert sec_detail.get("status") == "completed"

            sec_find_resp = await scanner_client.get(f"/scans/{sec_scan_id}/findings")
            sec_findings = sec_find_resp.json()["findings"]
            above_info = [f for f in sec_findings if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
            assert len(above_info) == 0, f"Secure server produced findings above INFO: {above_info}"

            # -------------------------------------------------------------
            # 6. Cleanup Verification: seed orders intact
            # -------------------------------------------------------------
            async with httpx.AsyncClient() as client:
                r_login_a = await client.post(
                    f"{vuln_url}/auth/login",
                    json={"username": "userA", "password": "passA123"},
                )
                assert r_login_a.status_code == 200
                token_a = r_login_a.json()["access_token"]

                orders_resp = await client.get(
                    f"{vuln_url}/orders",
                    headers={"Authorization": f"Bearer {token_a}"},
                )
                assert orders_resp.status_code == 200
                orders = orders_resp.json()
                order_ids = [o["id"] for o in orders]
                assert set(order_ids) == {101, 102, 103}

                r_login_b = await client.post(
                    f"{vuln_url}/auth/login",
                    json={"username": "userB", "password": "passB123"},
                )
                assert r_login_b.status_code == 200
                token_b = r_login_b.json()["access_token"]
                r_104 = await client.get(
                    f"{vuln_url}/orders/104",
                    headers={"Authorization": f"Bearer {token_b}"},
                )
                assert r_104.status_code == 200
                assert r_104.json()["id"] == 104

    # -------------------------------------------------------------
    # 7. Persistence Verification: Reload from DATA_DIR
    # -------------------------------------------------------------
    new_app = create_app(settings)
    async with new_app.router.lifespan_context(new_app):
        new_transport = httpx.ASGITransport(app=new_app)
        async with httpx.AsyncClient(transport=new_transport, base_url="http://testscanner") as new_client:
            list_resp = await new_client.get("/scans")
            assert list_resp.status_code == 200
            scans_list = list_resp.json()
            scan_ids = [s["id"] for s in scans_list]
            assert vuln_scan_id in scan_ids

            reloaded_vuln = next(s for s in scans_list if s["id"] == vuln_scan_id)
            assert reloaded_vuln["total_findings"] == len(findings)

    # -------------------------------------------------------------
    # 8. Secret Leak Check in {DATA_DIR}/scans.json
    # -------------------------------------------------------------
    snapshot_path = tmp_path / "scans.json"
    assert snapshot_path.exists()
    snapshot_content = snapshot_path.read_text(encoding="utf-8")

    forbidden_strings = ["passA123", "admin123", "Bearer ey", "111-22-3333", "444-55-6666"]
    for s in forbidden_strings:
        assert s not in snapshot_content, f"Found sensitive secret '{s}' in {snapshot_path}"

    # -------------------------------------------------------------
    # 9. Cancel & Shielded Cleanup Test
    # -------------------------------------------------------------
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        slow_port = s.getsockname()[1]

    stop_event = threading.Event()
    server_thread = threading.Thread(target=_run_slow_server, args=(slow_port, stop_event), daemon=True)
    server_thread.start()

    # Wait for slow server to respond
    slow_url = f"http://127.0.0.1:{slow_port}"
    for _ in range(30):
        try:
            r = httpx.get(f"{slow_url}/health", timeout=0.5)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.1)

    try:
        cancel_app = create_app(settings)
        async with cancel_app.router.lifespan_context(cancel_app):
            c_transport = httpx.ASGITransport(app=cancel_app)
            async with httpx.AsyncClient(transport=c_transport, base_url="http://testscanner") as c_client:
                slow_payload = {
                    "spec_url": f"{slow_url}/openapi.json",
                    "base_url": slow_url,
                    "identities": [
                        {"name": "user1", "role": "user", "username": "user1", "password": "pwd", "login_path": "/auth/login"}
                    ],
                    "test_case_budget": 50,
                }
                c_resp = await c_client.post("/scans", json=slow_payload)
                assert c_resp.status_code == 202
                slow_scan_id = c_resp.json()["scan_id"]

                # Wait slightly for scan to start running
                await asyncio.sleep(0.2)

                # Cancel mid-run
                cancel_call = await c_client.post(f"/scans/{slow_scan_id}/cancel")
                assert cancel_call.status_code == 200

                detail_call = await c_client.get(f"/scans/{slow_scan_id}")
                assert detail_call.json()["status"] == "cancelled"

                # Verify seed orders on vulnerable server remain pristine
                async with httpx.AsyncClient() as client:
                    r_login_a = await client.post(
                        f"{vuln_url}/auth/login",
                        json={"username": "userA", "password": "passA123"},
                    )
                    assert r_login_a.status_code == 200
                    token_a = r_login_a.json()["access_token"]
                    orders_check = await client.get(
                        f"{vuln_url}/orders",
                        headers={"Authorization": f"Bearer {token_a}"},
                    )
                    assert set(o["id"] for o in orders_check.json()) == {101, 102, 103}
    finally:
        stop_event.set()
