"""Input Handling & Robustness check (OWASP API8:2023 - Security Misconfiguration).

Note: This check tests input handling and edge-case boundary stability.
This is NOT an injection scanner (SQLi/XSS/Command injection are out of scope).
It observes whether malformed, boundary, or invalid-type identifiers cause unhandled
server crashes (5xx) or unexpected success (200 OK) for nonexistent identifiers.
"""

import logging
from typing import Any

from app.engine.checks.base import BaseCheck, register_check
from app.engine.checks.common import make_finding, provisional_severity
from app.engine.context import ScanContext
from app.engine.differential import compare, is_success
from app.engine.risk import RiskInputs
from app.engine.runner import run_cases
from app.engine.test_generator import TestCategory
from app.models import Finding

logger = logging.getLogger(__name__)

NONEXISTENT_PROBE_IDS = {
    "0",
    "-1",
    "999999999",
    "00000000-0000-0000-0000-000000000000",
    "99999999-9999-9999-9999-999999999999",
}


class InputHandlingCheck(BaseCheck):
    """Evaluates API stability on boundary and invalid-type inputs.

    Never claims injection vulnerabilities; evaluates crash behavior and nonexistent object handling.
    """

    name: str = "input_handling"
    owasp_id: str = "API8:2023"
    description: str = (
        "Consumes boundary and invalid-type test cases to detect unhandled 5xx server errors "
        "or anomalous 200 OK responses for nonexistent object identifiers."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """Execute boundary and invalid-type cases and flag crashes or phantom data."""
        findings: list[Finding] = []

        target_cases = [
            c
            for c in ctx.cases
            if c.category in (TestCategory.BOUNDARY, TestCategory.INVALID_TYPE)
            and c.endpoint.method.upper() == "GET"
        ]

        if not target_cases:
            return findings

        results = await run_cases(ctx, target_cases)

        for res in results:
            # 1. Check for unhandled 5xx server crashes
            if 500 <= res.response.status <= 599:
                risk_inputs = RiskInputs(
                    check_name="input_handling",
                    method=res.case.endpoint.method,
                    is_privileged_endpoint=False,
                    requires_auth=res.case.endpoint.requires_auth,
                    object_id_sequential=False,
                    diff=None,
                    attacker_identity_role=res.case.identity_name,
                    base_confidence=0.70,
                    has_data=False,
                )
                finding = make_finding(
                    check="input_handling",
                    endpoint=res.case.endpoint,
                    title="Unhandled server error on malformed identifier",
                    confidence=0.70,
                    explanation=(
                        f"Endpoint '{res.case.endpoint.path}' crashed with HTTP {res.response.status} "
                        f"when queried with {res.case.category.value} identifier '{res.case.object_id}'. "
                        f"The server failed to handle invalid input gracefully."
                    ),
                    fix_hint=(
                        "Add input validation and error handling to reject invalid parameter formats "
                        "with HTTP 400 Bad Request or HTTP 422 Unprocessable Entity instead of 5xx."
                    ),
                    identity_name=res.case.identity_name,
                    request=res.request,
                    attack_response=res.response,
                    baseline_response=res.baseline_response,
                    object_id=res.case.object_id,
                    expected_status=400,
                    owasp_id=self.owasp_id,
                    risk_inputs=risk_inputs,
                )
                findings.append(finding)

            # 2. Check for 2xx with data returned on nonexistent / boundary identifier
            elif is_success(res.response.status):
                diff = compare(
                    baseline=None,
                    attack=res.response,
                    requested_object_id=res.case.object_id,
                )

                if diff.attack_body_is_error or diff.attack_body_empty:
                    continue

                obj_str = str(res.case.object_id)
                is_probe = obj_str in NONEXISTENT_PROBE_IDS or "nonexistent" in obj_str.lower()

                has_id = False
                if isinstance(res.response.body, dict):
                    has_id = any(
                        k.lower() in ("id", "uuid", f"{res.case.endpoint.resource}_id")
                        for k in res.response.body.keys()
                    )

                if is_probe and has_id:
                    confidence = 0.60
                    if confidence >= ctx.settings.MIN_REPORT_CONFIDENCE:
                        risk_inputs_exist = RiskInputs(
                            check_name="input_handling",
                            method=res.case.endpoint.method,
                            is_privileged_endpoint=False,
                            requires_auth=res.case.endpoint.requires_auth,
                            object_id_sequential=False,
                            diff=diff,
                            attacker_identity_role=res.case.identity_name,
                            base_confidence=confidence,
                            has_data=True,
                        )
                        finding = make_finding(
                            check="input_handling",
                            endpoint=res.case.endpoint,
                            title="Server returns data for nonexistent object",
                            confidence=confidence,
                            explanation=(
                                f"Endpoint '{res.case.endpoint.path}' returned HTTP {res.response.status} with a "
                                f"valid object payload when queried with nonexistent identifier '{res.case.object_id}'."
                            ),
                            fix_hint="Verify object existence before returning HTTP 200. Return HTTP 404 when the object is missing.",
                            identity_name=res.case.identity_name,
                            request=res.request,
                            attack_response=res.response,
                            baseline_response=res.baseline_response,
                            diff_result=diff,
                            object_id=res.case.object_id,
                            expected_status=404,
                            owasp_id=self.owasp_id,
                            risk_inputs=risk_inputs_exist,
                        )
                        findings.append(finding)

        return findings


# Register the check
register_check(InputHandlingCheck())
