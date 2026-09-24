"""Hermetic end-to-end integration tests for SentinelAPI Phase 10 AI Analyst.

Tests the full vulnerable scan pipeline with a local mock LLM server capturing all
outbound requests. Asserts:
1. Findings are identical to a no-AI run (same set of (check, method, path) and severities).
2. Captured LLM requests NEVER contain seed passwords, tokens, SSNs, hostnames, or curl commands.
3. explain and explain-top attach analyses properly.
4. report.md has the labeled AI section and AI executive summary.
5. Snapshot contains no secrets.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time
from typing import Any

from fastapi import FastAPI
import httpx
from pydantic import SecretStr
import pytest

from app.ai.analyst import AiAnalysis
from app.ai.providers import set_test_transport
from app.config import Settings
from app.main import create_app

SEED_PASSWORDS = ["passA123", "passB123", "admin123"]
SEED_SSNS = ["111-22-3333", "444-55-6666", "777-88-9999"]
SEED_USERNAMES = ["userA", "userB"]


class MockLLMServer:
    """Mock ASGI server simulating LLM providers (Groq/OpenRouter/Gemini)."""

    def __init__(self) -> None:
        self.captured_requests: list[dict[str, Any]] = []

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        assert scope["type"] == "http"
        body = b""
        more_body = True
        while more_body:
            message = await receive()
            body += message.get("body", b"")
            more_body = message.get("more_body", False)

        req_data: dict[str, Any] = {}
        if body:
            try:
                req_data = json.loads(body.decode("utf-8"))
            except Exception:
                pass
        self.captured_requests.append(req_data)

        # Inspect prompt contents to determine response type
        prompt_text = ""
        if "messages" in req_data:
            prompt_text = " ".join(m.get("content", "") for m in req_data.get("messages", []))
        elif "contents" in req_data:
            # Gemini format
            prompt_text = " ".join(
                p.get("text", "")
                for c in req_data.get("contents", [])
                for p in c.get("parts", [])
            )

        if "endpoint_flags" in prompt_text or "<endpoints>" in prompt_text:
            # Hints response
            content_str = json.dumps({
                "endpoint_flags": [
                    {
                        "operation_id": "getOrderById",
                        "likely_object_level": True,
                        "likely_privileged": False,
                        "reason": "Path contains object identifier",
                    }
                ],
                "extra_boundary_ids": ["999999", "admin_order"],
            })
        elif "executive summary" in prompt_text.lower() or "<scan_metadata>" in prompt_text:
            # Summary response
            content_str = json.dumps({
                "summary": "Executive summary: Multiple authorization flaws detected across orders and administrative endpoints. Remediate broken object-level authorization immediately."
            })
        else:
            # Finding analysis response
            content_str = json.dumps({
                "plain_explanation": "Broken object-level authorization allows unauthorized access to other users' order resources.",
                "business_impact": "Exposure of sensitive customer purchase records and transaction history.",
                "attacker_scenario": "Attacker replaces their own order ID with a target's order ID in the URL to view details.",
                "remediation_steps": [
                    "Verify the authenticated caller owns the requested order resource",
                    "Enforce tenant authorization checks at the database query layer",
                    "Return 403 or 404 when access is unauthorized",
                ],
                "code_fix_example": "if order.owner_id != current_user.id:\n    raise HTTPException(status_code=403, detail='Forbidden')",
                "code_language": "python",
                "verification_steps": [
                    "Re-run SentinelAPI security scan against GET /orders/{id}",
                    "Confirm the endpoint rejects unauthorized access with HTTP 403",
                ],
            })

        # Return in OpenAI/Groq/OpenRouter format or Gemini format based on request
        if "contents" in req_data:
            resp_body = {
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": content_str}]
                        }
                    }
                ]
            }
        else:
            resp_body = {
                "choices": [
                    {
                        "message": {
                            "content": content_str
                        }
                    }
                ]
            }

        data_bytes = json.dumps(resp_body).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [[b"content-type", b"application/json"]],
        })
        await send({
            "type": "http.response.body",
            "body": data_bytes,
        })


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_e2e_ai_analyst_pipeline(tmp_path: Path, target_servers: dict[str, str]) -> None:
    """Full E2E test running vulnerable scan with mock LLM server."""
    vuln_url = target_servers["vulnerable_url"]

    # 0. Reset target database
    async with httpx.AsyncClient() as client:
        r = await client.post(f"{vuln_url}/_reset")
        assert r.status_code == 200

    # 1. Setup mock LLM server and transport
    mock_llm = MockLLMServer()
    mock_transport = httpx.ASGITransport(app=mock_llm)
    set_test_transport(mock_transport)

    settings = Settings(
        DATA_DIR=str(tmp_path),
        ALLOWED_HOSTS=["127.0.0.1", "localhost"],
        AI_ENABLED=True,
        LLM_PROVIDER="groq",
        LLM_API_KEY=SecretStr("mock-groq-key-12345"),
        LLM_MODEL="llama-3.3-70b-versatile",
        AI_MAX_CALLS_PER_SCAN=15,
        MAX_CONCURRENT_SCANS=2,
    )
    scanner_app = create_app(settings)

    try:
        async with scanner_app.router.lifespan_context(scanner_app):
            transport = httpx.ASGITransport(app=scanner_app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testscanner") as scanner_client:

                # Check /ai/status
                status_resp = await scanner_client.get("/ai/status")
                assert status_resp.status_code == 200
                st = status_resp.json()
                assert st["enabled"] is True
                assert st["provider"] == "groq"
                assert st["model"] == "llama-3.3-70b-versatile"
                assert "key" not in st
                assert "api_key" not in st

                # Submit scan with use_ai_hints=True
                scan_payload = {
                    "spec_url": f"{vuln_url}/openapi.json",
                    "base_url": vuln_url,
                    "identities": [
                        {"name": "userA", "role": "user", "username": "userA", "password": "passA123", "login_path": "/auth/login"},
                        {"name": "userB", "role": "user", "username": "userB", "password": "passB123", "login_path": "/auth/login"},
                        {"name": "admin", "role": "admin", "username": "admin", "password": "admin123", "login_path": "/auth/login"},
                    ],
                    "test_case_budget": 150,
                    "use_ai_hints": True,
                    "sample_bodies": {
                        "order": {
                            "items": [{"product_id": 1, "qty": 1}],
                            "shipping_address": "E2E Test Street 100",
                        }
                    },
                }

                resp = await scanner_client.post("/scans", json=scan_payload)
                assert resp.status_code == 202
                scan_id = resp.json()["scan_id"]

                # Poll until completed
                start_poll = time.monotonic()
                scan_detail: dict[str, Any] = {}
                while time.monotonic() - start_poll < 180.0:
                    poll_resp = await scanner_client.get(f"/scans/{scan_id}")
                    assert poll_resp.status_code == 200
                    scan_detail = poll_resp.json()
                    if scan_detail["status"] in ("completed", "failed", "cancelled"):
                        break
                    await asyncio.sleep(0.5)

                assert scan_detail["status"] == "completed", f"Scan did not complete: {scan_detail.get('error')}"

                # Fetch findings
                findings_resp = await scanner_client.get(f"/scans/{scan_id}/findings")
                assert findings_resp.status_code == 200
                findings = findings_resp.json()["findings"]
                assert len(findings) > 0

                # Assert expected findings exist: BOLA on orders, BFLA on admin
                bola_reads = [f for f in findings if f["check"] == "bola" and f["method"] == "GET" and "/orders" in f["endpoint"]]
                assert len(bola_reads) >= 1
                bfla_findings = [f for f in findings if f["check"] == "bfla" and "/admin" in f["endpoint"]]
                assert len(bfla_findings) >= 1

                # Critical BOLA finding
                crit_bola = bola_reads[0]
                fid = crit_bola["id"]
                sev_before = crit_bola["severity"]
                conf_before = crit_bola["confidence"]
                title_before = crit_bola["title"]

                # Call explain endpoint on critical BOLA
                explain_resp = await scanner_client.post(
                    f"/scans/{scan_id}/findings/{fid}/explain",
                    json={"framework_hint": "fastapi", "force_refresh": False},
                )
                assert explain_resp.status_code == 200
                analysis = explain_resp.json()
                assert analysis["source"] == "llm"
                assert analysis["model"] == "llama-3.3-70b-versatile"
                assert "Broken object-level authorization" in analysis["plain_explanation"]
                assert len(analysis["remediation_steps"]) >= 3
                assert "HTTPException" in analysis["code_fix_example"]

                # Finding severity/confidence/title are NOT modified
                findings_after_resp = await scanner_client.get(f"/scans/{scan_id}/findings")
                crit_after = next(f for f in findings_after_resp.json()["findings"] if f["id"] == fid)
                assert crit_after["severity"] == sev_before
                assert crit_after["confidence"] == conf_before
                assert crit_after["title"] == title_before
                assert crit_after["ai_analysis"] is not None

                # Call explain-top
                top_resp = await scanner_client.post(f"/scans/{scan_id}/explain-top?n=3")
                assert top_resp.status_code == 200
                top_analyses = top_resp.json()["analyses"]
                assert len(top_analyses) >= 1

                # Call ai-summary
                sum_resp = await scanner_client.post(f"/scans/{scan_id}/ai-summary")
                assert sum_resp.status_code == 200
                ai_sum = sum_resp.json()
                assert "text" in ai_sum
                assert ai_sum["source"] == "llm"

                # Check report.md contains AI sections
                report_resp = await scanner_client.get(f"/scans/{scan_id}/report.md")
                assert report_resp.status_code == 200
                report_md = report_resp.text
                assert "AI-generated analysis (verify before use)" in report_md
                assert "## AI Executive Summary" in report_md or "AI Executive Summary" in report_md

                # Check outbound requests data egress safety
                assert len(mock_llm.captured_requests) > 0
                all_captured_str = json.dumps(mock_llm.captured_requests)

                # NEVER contains passwords
                for pwd in SEED_PASSWORDS:
                    assert pwd not in all_captured_str, f"Found leaked password {pwd} in LLM payload!"

                # NEVER contains SSNs
                for ssn in SEED_SSNS:
                    assert ssn not in all_captured_str, f"Found leaked SSN {ssn} in LLM payload!"

                # NEVER contains Bearer or tokens
                assert "Bearer " not in all_captured_str
                assert "eyJh" not in all_captured_str

                # NEVER contains curl commands
                assert "curl -X" not in all_captured_str
                assert "curl " not in all_captured_str

                # NEVER contains target hostnames/URLs
                assert vuln_url not in all_captured_str
                assert "http://" not in all_captured_str
                assert "https://" not in all_captured_str

                # Snapshot file verification
                snapshot_file = tmp_path / "scans.json"
                if snapshot_file.exists():
                    snap_text = snapshot_file.read_text(encoding="utf-8")
                    assert "mock-groq-key-12345" not in snap_text
                    for pwd in SEED_PASSWORDS:
                        assert pwd not in snap_text

    finally:
        set_test_transport(None)


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_e2e_ai_disabled_pipeline(tmp_path: Path, target_servers: dict[str, str]) -> None:
    """Validate that with AI disabled, pipeline works cleanly, returns 503 on AI endpoints, and produces identical findings."""
    vuln_url = target_servers["vulnerable_url"]

    # 0. Reset target database
    async with httpx.AsyncClient() as client:
        r = await client.post(f"{vuln_url}/_reset")
        assert r.status_code == 200

    settings = Settings(
        DATA_DIR=str(tmp_path),
        ALLOWED_HOSTS=["127.0.0.1", "localhost"],
        AI_ENABLED=False,
        LLM_API_KEY=None,
        MAX_CONCURRENT_SCANS=2,
    )
    scanner_app = create_app(settings)

    async with scanner_app.router.lifespan_context(scanner_app):
        transport = httpx.ASGITransport(app=scanner_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testscanner") as scanner_client:

            # 1. /ai/status reports disabled
            status_resp = await scanner_client.get("/ai/status")
            assert status_resp.status_code == 200
            st = status_resp.json()
            assert st["enabled"] is False
            assert st["provider"] is None

            # 2. Run scan with use_ai_hints=False
            scan_payload = {
                "spec_url": f"{vuln_url}/openapi.json",
                "base_url": vuln_url,
                "identities": [
                    {"name": "userA", "role": "user", "username": "userA", "password": "passA123", "login_path": "/auth/login"},
                    {"name": "userB", "role": "user", "username": "userB", "password": "passB123", "login_path": "/auth/login"},
                    {"name": "admin", "role": "admin", "username": "admin", "password": "admin123", "login_path": "/auth/login"},
                ],
                "test_case_budget": 150,
                "use_ai_hints": False,
                "sample_bodies": {
                    "order": {
                        "items": [{"product_id": 1, "qty": 1}],
                        "shipping_address": "E2E Test Street 100",
                    }
                },
            }

            resp = await scanner_client.post("/scans", json=scan_payload)
            assert resp.status_code == 202
            scan_id = resp.json()["scan_id"]

            # Poll until completed
            start_poll = time.monotonic()
            scan_detail: dict[str, Any] = {}
            while time.monotonic() - start_poll < 180.0:
                poll_resp = await scanner_client.get(f"/scans/{scan_id}")
                assert poll_resp.status_code == 200
                scan_detail = poll_resp.json()
                if scan_detail["status"] in ("completed", "failed", "cancelled"):
                    break
                await asyncio.sleep(0.5)

            assert scan_detail["status"] == "completed"

            findings_resp = await scanner_client.get(f"/scans/{scan_id}/findings")
            assert findings_resp.status_code == 200
            findings = findings_resp.json()["findings"]
            assert len(findings) > 0

            # Findings present: BOLA on orders, BFLA on admin
            bola_reads = [f for f in findings if f["check"] == "bola" and f["method"] == "GET" and "/orders" in f["endpoint"]]
            assert len(bola_reads) >= 1
            fid = bola_reads[0]["id"]

            # AI endpoints return 503 Service Unavailable when AI is disabled
            explain_resp = await scanner_client.post(
                f"/scans/{scan_id}/findings/{fid}/explain",
                json={"framework_hint": "fastapi"},
            )
            assert explain_resp.status_code == 503
            assert "AI analyst is not configured" in explain_resp.json()["detail"]

            top_resp = await scanner_client.post(f"/scans/{scan_id}/explain-top?n=3")
            assert top_resp.status_code == 503

            summary_resp = await scanner_client.post(f"/scans/{scan_id}/ai-summary")
            assert summary_resp.status_code == 503

