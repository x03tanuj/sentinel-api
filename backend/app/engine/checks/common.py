"""Shared finding construction and risk evaluation helpers for security checks."""

import logging
from typing import Any

from app.engine.differential import DiffResult
from app.engine.evidence import build_evidence, curl_for_evidence
from app.engine.risk import RiskInputs, compute_severity
from app.models import Endpoint, Finding, RequestRecord, ResponseRecord, Severity

logger = logging.getLogger(__name__)

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
        Maintained as a documented fallback if RiskEngine raises during evaluation.

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
    risk_inputs: RiskInputs | None = None,
) -> Finding:
    """Construct a clean, sanitized Finding model with linked Evidence and risk scoring.

    Guarantees:
    - Evidence artifacts are scrubbed of credentials with defense-in-depth sanitization.
    - Copy-paste curl PoCs use $TOKEN placeholders.
    - Severity and risk sub-scores are calculated via the Risk Engine, with provisional_severity
      used solely as a safe fallback path.

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
        severity: Optional explicit severity override.
        owasp_id: Optional OWASP identifier; defaults to standard 2023 mapping.
        risk_inputs: Optional RiskInputs for standardized severity and breakdown calculation.

    Returns:
        Fully populated Finding model.
    """
    resolved_owasp = owasp_id or OWASP_MAP.get(check.lower(), "API1:2023")
    has_data = attack_response.body is not None and attack_response.size > 2

    # 1. Evaluate severity via RiskEngine with provisional fallback
    calc_severity: Severity | None = severity
    risk_score: int | None = None
    risk_breakdown: dict[str, int] | None = None

    if risk_inputs is not None:
        try:
            sev_res = compute_severity(risk_inputs)
            if calc_severity is None:
                calc_severity = sev_res[0]
            risk_score = sev_res[1]
            risk_breakdown = getattr(
                sev_res,
                "breakdown",
                {
                    "impact": 0,
                    "exploitability": 0,
                    "sensitivity": 0,
                    "evidence_strength": 0,
                    "total": risk_score,
                },
            )
        except Exception as exc:
            logger.warning("compute_severity failed (%s); falling back to provisional_severity", exc)
            if calc_severity is None:
                calc_severity = provisional_severity(
                    check=check,
                    method=endpoint.method,
                    diff_result=diff_result,
                    has_data=has_data,
                )
    elif calc_severity is None:
        calc_severity = provisional_severity(
            check=check,
            method=endpoint.method,
            diff_result=diff_result,
            has_data=has_data,
        )

    # 2. Build structured, sanitized technical Evidence
    evidence = build_evidence(
        case_result_or_context=None,
        request=request,
        baseline_response=baseline_response,
        attack_response=attack_response,
        diff=diff_result,
        identity=identity_name,
        object_id=object_id,
        expected_status=expected_status,
    )

    if risk_score is not None:
        evidence.response_diff["risk_score"] = risk_score
    if risk_breakdown is not None:
        evidence.response_diff["risk_breakdown"] = risk_breakdown

    # 3. Generate curl PoC from scrubbed Evidence request
    curl_poc = curl_for_evidence(evidence)

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
