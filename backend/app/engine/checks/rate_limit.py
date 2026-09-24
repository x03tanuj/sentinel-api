"""Unrestricted Resource Consumption / Lack of Rate Limiting check (OWASP API4:2023).

Tests sensitive unauthenticated endpoints (login, token, auth) against rapid request bursts
to verify that rate limiting protections (HTTP 429 / Retry-After) are strictly enforced.
"""

import logging
import re
import time
from typing import Any

from app.engine.checks.base import BaseCheck, register_check
from app.engine.checks.common import make_finding, provisional_severity
from app.engine.context import ScanContext
from app.engine.risk import RiskInputs
from app.engine.differential import DiffResult
from app.engine.errors import BudgetExceededError, TargetUnreachableError
from app.engine.http_executor import build_url
from app.models import Endpoint, Finding, RequestRecord, ResponseRecord, Severity

logger = logging.getLogger(__name__)

SENSITIVE_PATH_PATTERN = re.compile(
    r"login|signin|token|auth|password|otp|reset",
    re.IGNORECASE,
)


class RateLimitCheck(BaseCheck):
    """Detects missing or ineffective rate limiting on sensitive authentication routes.

    Safety:
    Runs LAST and sequentially after all other checks to ensure request bursts do not
    interfere with, lock out, or throttle other test cases.
    """

    name: str = "rate_limit"
    owasp_id: str = "API4:2023"
    description: str = (
        "Validates that sensitive unauthenticated POST endpoints (e.g. login, token) enforce "
        "rate limiting and return HTTP 429 after rapid sequential failed attempts."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """Execute rate limit probing against sensitive unauthenticated POST endpoints."""
        findings: list[Finding] = []

        target_endpoints: list[Endpoint] = []
        for ep in ctx.endpoints:
            if ep.method.upper() != "POST":
                continue
            if ep.requires_auth:
                continue
            if ep.path.startswith("/_") or ep.path.startswith("/health") or ep.path.startswith("/metrics"):
                continue

            matches_path = bool(SENSITIVE_PATH_PATTERN.search(ep.path))
            matches_op = bool(ep.operation_id and SENSITIVE_PATH_PATTERN.search(ep.operation_id))

            if matches_path or matches_op:
                target_endpoints.append(ep)

        if not target_endpoints:
            return findings

        probe_count = ctx.settings.RATE_LIMIT_PROBE_COUNT

        for ep in target_endpoints:
            url = build_url(ctx.base_url, ep.path)

            # Construct invalid probe payload matching schema if possible
            payload: dict[str, Any] = {
                "username": "sentinel-probe-user",
                "password": "ProbePassword123!",
            }
            if ep.body_schema and isinstance(ep.body_schema, dict):
                props = ep.body_schema.get("properties", {})
                if "email" in props:
                    payload["email"] = "sentinel-probe-user@example.com"
                if "identifier" in props:
                    payload["identifier"] = "sentinel-probe-user"

            responses: list[tuple[RequestRecord, ResponseRecord]] = []
            latencies: list[float] = []
            rate_limited = False
            start_time = time.monotonic()

            for i in range(1, probe_count + 1):
                try:
                    req_rec, resp_rec = await ctx.executor.execute(
                        method="POST",
                        url=url,
                        identity=None,  # Unauthenticated
                        json_body=payload,
                    )
                except BudgetExceededError:
                    ctx.notes.append("rate_limit check stopped: request budget exceeded")
                    return findings
                except TargetUnreachableError as exc:
                    ctx.notes.append(f"rate_limit target unreachable for {ep.path}: {exc}")
                    break
                except Exception as exc:
                    ctx.notes.append(f"rate_limit error on {ep.path}: {type(exc).__name__}")
                    break

                responses.append((req_rec, resp_rec))
                latencies.append(resp_rec.latency_ms)

                # Check if rate limiting kicked in
                has_rate_limit_header = any(
                    h.lower().startswith("x-ratelimit") or h.lower() == "retry-after"
                    for h in resp_rec.headers
                )
                if resp_rec.status in (429, 503) or (resp_rec.status == 403 and has_rate_limit_header):
                    rate_limited = True
                    ctx.notes.append(f"rate limiting observed on {ep.path} after {i} requests")
                    break

            if rate_limited or not responses:
                continue

            end_time = time.monotonic()
            total_duration = max(end_time - start_time, 0.001)
            burst_rate = len(responses) / total_duration

            # Latency check: last 5 latency vs first 5 latency
            latency_slowdown = False
            if len(latencies) >= 10:
                first_5_avg = sum(latencies[:5]) / 5.0
                last_5_avg = sum(latencies[-5:]) / 5.0
                if first_5_avg > 0 and (last_5_avg > 2.0 * first_5_avg) and (last_5_avg - first_5_avg > 25.0):
                    latency_slowdown = True

            # If no 429/503, no rate-limit headers, and latency didn't slow down significantly
            if not latency_slowdown:
                confidence = 0.80 if burst_rate >= 5.0 else 0.60
                if confidence >= ctx.settings.MIN_REPORT_CONFIDENCE:
                    last_req, last_resp = responses[-1]
                    diff_res = DiffResult(
                        status_changed=False,
                        baseline_status=responses[0][1].status,
                        attack_status=last_resp.status,
                        body_similarity=1.0,
                        schema_similarity=1.0,
                        same_object_id=None,
                        owner_id_differs=None,
                        sensitive_fields_exposed={},
                        size_ratio=1.0,
                        changed_fields=[],
                        attack_body_empty=False,
                        attack_body_is_error=False,
                    )
                    risk_inputs = RiskInputs(
                        check_name="rate_limit",
                        method=ep.method,
                        is_privileged_endpoint=False,
                        requires_auth=False,
                        object_id_sequential=False,
                        diff=diff_res,
                        attacker_identity_role="anonymous",
                        base_confidence=confidence,
                    )
                    finding = make_finding(
                        check="rate_limit",
                        endpoint=ep,
                        title=f"Missing Rate Limiting on {ep.path}",
                        confidence=confidence,
                        explanation=(
                            f"Endpoint '{ep.path}' processed {len(responses)} rapid sequential authentication requests "
                            f"without enforcing rate limits (actual burst rate: {burst_rate:.1f} req/s). "
                            f"No HTTP 429 or rate-limiting headers were observed. Note: scanner sends at most "
                            f"{ctx.settings.MAX_RPS} requests per second, so limits looser than that are not detected."
                        ),
                        fix_hint=(
                            "Implement strict rate limiting on sensitive unauthenticated endpoints. "
                            "Return HTTP 429 Too Many Requests with a Retry-After header after multiple rapid attempts."
                        ),
                        identity_name="anonymous",
                        request=last_req,
                        attack_response=last_resp,
                        baseline_response=responses[0][1],
                        diff_result=diff_res,
                        expected_status=429,
                        owasp_id=self.owasp_id,
                        risk_inputs=risk_inputs,
                    )
                    findings.append(finding)

        return findings


# Register the check
register_check(RateLimitCheck())
