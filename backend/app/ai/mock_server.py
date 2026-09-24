"""Standalone Mock LLM Server for End-to-End Testing (Docker / Playwright).

Simulates Groq, OpenRouter, and Gemini completions without external network egress.
Captures requests for verification that no secrets or customer hosts were leaked.
"""

from __future__ import annotations

import json
import logging
from typing import Any
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

logger = logging.getLogger("mock_llm")
logging.basicConfig(level=logging.INFO)

captured_requests: list[dict[str, Any]] = []


async def health(request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")


async def captured(request: Request) -> JSONResponse:
    return JSONResponse({"count": len(captured_requests), "requests": captured_requests})


async def handle_completion(request: Request) -> JSONResponse:
    try:
        req_data = await request.json()
    except Exception:
        req_data = {}

    captured_requests.append(req_data)
    logger.info("Captured LLM completion request: keys=%s", list(req_data.keys()))

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
        content_str = json.dumps({
            "summary": "Executive summary: Multiple authorization flaws detected across orders and administrative endpoints. Remediate broken object-level authorization immediately."
        })
    else:
        # Standard finding analysis
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

    if "contents" in req_data:
        # Gemini format
        return JSONResponse({
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": content_str}]
                    }
                }
            ]
        })

    # Groq / OpenRouter OpenAI-compatible format
    return JSONResponse({
        "choices": [
            {
                "message": {
                    "content": content_str
                }
            }
        ]
    })


app = Starlette(
    routes=[
        Route("/health", health, methods=["GET"]),
        Route("/captured", captured, methods=["GET"]),
        Route("/openai/v1/chat/completions", handle_completion, methods=["POST"]),
        Route("/api/v1/chat/completions", handle_completion, methods=["POST"]),
        Route("/{path:path}", handle_completion, methods=["POST"]),
    ]
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
