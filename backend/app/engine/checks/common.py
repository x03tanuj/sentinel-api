"""Shared finding construction and provisional severity helpers for security checks."""

from typing import Any

from app.engine.differential import DiffResult, summarize_diff_for_evidence
from app.engine.http_executor import generate_curl
from app.engine.redaction import redact_response
from app.models import Endpoint, Evidence, Finding, RequestRecord, ResponseRecord, Severity

OWASP_MAP: dict[str, str] = {
    "bola": "API1:2023",
    "unauth_access": "API2:2023",
    "data_exposure": "API3:2023",
    "rate_limit": "API4:2023",
    "bfla": "API5:2023",
    "input_handling": "API8:2023",
}


def provisional_severity(
    check: str,
    method: str = "GET",
    diff_result: DiffResult | None = None,
    has_data: bool = True,
) -> Severity:
    """Determine provisional vulnerability severity for a check finding.

    Note:
        Provisional. Phase 7 replaces this with the Risk Engine.

    Rules:
    - BOLA write (PUT/PATCH/DELETE) -> CRITICAL
    - BOLA read (GET) -> HIGH
    - BFLA -> HIGH
    - Unauthenticated access -> HIGH when data returned else MEDIUM
    - Data exposure -> HIGH if SECRET tier fields, MEDIUM if PERSONAL/undeclared, else LOW
    - Rate limiting -> MEDIUM
    - Input handling / robustness -> INFO

    Args:
        check: Security check module name.
        method: HTTP method.
        diff_result: Optional DiffResult from response comparison.
        has_data: Whether response payload contained meaningful data.

    Returns:
        Provisional Severity rating.
    """
    check_lower = check.lower()

    if "bola" in check_lower:
        if method.upper() in ("PUT", "PATCH", "DELETE"):
            return Severity.CRITICAL
        return Severity.HIGH

    if "bfla" in check_lower:
        return Severity.HIGH

    if "unauth" in check_lower:
        return Severity.HIGH if has_data else Severity.MEDIUM

    if "data_exposure" in check_lower:
        if diff_result and diff_result.sensitive_fields_exposed.get("SECRET"):
            return Severity.HIGH
        if diff_result and diff_result.sensitive_fields_exposed.get("PERSONAL"):
            return Severity.MEDIUM
        return Severity.LOW

    if "rate_limit" in check_lower:
        return Severity.MEDIUM

    if "input_handling" in check_lower:
        return Severity.INFO

    return Severity.MEDIUM


def make_finding(
    check: str,
    endpoint: Endpoint,
    title: str,
    confidence: float,
    explanation: str,
    fix_hint: str,
    identity_name: str,
    request: RequestRecord,
    attack_response: ResponseRecord,
    baseline_response: ResponseRecord | None = None,
    diff_result: DiffResult | None = None,
    object_id: str | None = None,
    expected_status: int | None = None,
    severity: Severity | None = None,
    owasp_id: str | None = None,
) -> Finding:
    """Construct a clean, sanitized Finding model with linked Evidence.

    Guarantees that credentials in request/response records are scrubbed and
    that copy-paste curl PoCs use $TOKEN placeholders.

    Args:
        check: Identifier of the check module.
        endpoint: Target endpoint specification.
        title: Human-readable vulnerability title.
        confidence: Confidence score between 0.0 and 1.0.
        explanation: Clear description of the flaw and exploit proof.
        fix_hint: Remediation guidance.
        identity_name: Persona utilized to demonstrate vulnerability.
        request: RequestRecord from probe execution.
        attack_response: ResponseRecord from attack probe.
        baseline_response: Optional legitimate baseline ResponseRecord.
        diff_result: Optional DiffResult.
        object_id: Target object identifier.
        expected_status: Expected authorization status code.
        severity: Optional explicit severity; defaults to provisional calculation.
        owasp_id: Optional OWASP identifier; defaults to standard 2023 mapping.

    Returns:
        Fully populated Finding model.
    """
    resolved_owasp = owasp_id or OWASP_MAP.get(check.lower(), "API1:2023")

    has_data = attack_response.body is not None and attack_response.size > 2
    calc_severity = severity or provisional_severity(
        check=check,
        method=endpoint.method,
        diff_result=diff_result,
        has_data=has_data,
    )

    # Sanitize response diff for evidence
    resp_diff: dict[str, Any] = {}
    if diff_result is not None:
        resp_diff = summarize_diff_for_evidence(diff_result, attack_response)

    evidence = Evidence(
        identity=identity_name,
        object_id=object_id,
        expected_status=expected_status,
        actual_status=attack_response.status,
        request=request,  # headers already scrubbed by Executor
        baseline_response=redact_response(baseline_response) if baseline_response else None,
        attack_response=redact_response(attack_response),
        response_diff=resp_diff,
    )

    curl_poc = generate_curl(request)

    return Finding(
        check=check,
        endpoint=endpoint.path,
        method=endpoint.method.upper(),
        title=title,
        severity=calc_severity,
        confidence=min(1.0, max(0.0, float(confidence))),
        explanation=explanation,
        evidence=evidence,
        curl_poc=curl_poc,
        fix_hint=fix_hint,
        owasp_id=resolved_owasp,
    )
