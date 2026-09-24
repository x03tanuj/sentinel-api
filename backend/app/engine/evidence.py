"""Structured evidence collection, redaction enforcement, and PoC generation.

Provides a unified factory to construct sanitized Evidence artifacts with defense-in-depth
redaction guarantees, masked sensitive field values, and curl command reproduction strings.
"""

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from app.engine.auth_matrix import Outcome
from app.engine.differential import DiffResult, summarize_diff_for_evidence
from app.engine.http_executor import generate_curl
from app.engine.redaction import mask_value, redact_body, redact_headers, redact_response
from app.models import Evidence, Identity, RequestRecord, ResponseRecord


def _extract_field_values(data: Any, target_field: str) -> list[Any]:
    """Recursively search a JSON payload for values associated with target_field."""
    found: list[Any] = []
    target_lower = target_field.lower()
    if isinstance(data, dict):
        for k, v in data.items():
            if str(k).strip().lower() == target_lower:
                found.append(v)
            if isinstance(v, (dict, list)):
                found.extend(_extract_field_values(v, target_field))
    elif isinstance(data, list):
        for item in data:
            found.extend(_extract_field_values(item, target_field))
    return found


def build_evidence(
    case_result_or_context: Any,
    request: RequestRecord,
    baseline_response: ResponseRecord | None,
    attack_response: ResponseRecord,
    diff: DiffResult | None,
    identity: str | Identity,
    object_id: str | None,
    expected_status: int | None = None,
) -> Evidence:
    """Construct an Evidence artifact with defense-in-depth sanitization and differential analysis.

    Guarantees:
    - Requests and responses pass through header and body redaction regardless of caller state.
    - Raw secrets, SSNs, and Authorization tokens are scrubbed.
    - Sensitive exposed fields are masked via mask_value.
    - Expected HTTP status is automatically inferred if not explicitly specified.

    Args:
        case_result_or_context: CaseResult, TestCase, or ScanContext from which to infer outcomes.
        request: RequestRecord representing the probe dispatched.
        baseline_response: Legitimate ResponseRecord for comparison (if available).
        attack_response: Probing attack ResponseRecord.
        diff: Optional DiffResult from compare().
        identity: Probing persona name or Identity instance.
        object_id: Identifier of the probed resource object.
        expected_status: Expected HTTP status code (defaults to inference).

    Returns:
        Fully sanitized Evidence model.
    """
    # 1. Resolve identity name
    identity_name = identity.name if isinstance(identity, Identity) else str(identity)

    # 2. Defense-in-depth: Re-redact request headers and body
    clean_request = RequestRecord(
        method=request.method.upper(),
        url=request.url,
        headers_redacted=redact_headers(request.headers_redacted),
        body=redact_body(request.body),
    )

    # 3. Defense-in-depth: Re-redact response records
    clean_attack_response = redact_response(attack_response)
    clean_baseline_response = redact_response(baseline_response) if baseline_response else None

    # 4. Infer expected status if not explicitly passed
    resolved_expected_status = expected_status
    if resolved_expected_status is None:
        case_obj = None
        if hasattr(case_result_or_context, "case"):
            case_obj = getattr(case_result_or_context, "case")
        elif hasattr(case_result_or_context, "expected_outcome"):
            case_obj = case_result_or_context

        if case_obj is not None:
            outcome = getattr(case_obj, "expected_outcome", None)
            if outcome in (Outcome.ALLOW, "ALLOW"):
                resolved_expected_status = (
                    attack_response.status
                    if (200 <= attack_response.status <= 299)
                    else 200
                )
            else:
                # Expected DENY: 401 for anonymous/unauth, 403 for cross-user/forbidden
                identity_lower = identity_name.lower()
                if "anonymous" in identity_lower or "unauth" in identity_lower:
                    resolved_expected_status = 401
                else:
                    resolved_expected_status = 403
        else:
            resolved_expected_status = 403

    # 5. Summarize differential analysis and capture masked sensitive samples
    resp_diff: dict[str, Any] = {}
    if diff is not None:
        resp_diff = summarize_diff_for_evidence(diff, attack_response)
    else:
        resp_diff = {}

    # Extract and mask sensitive values for flagged fields
    masked_sensitive_values: dict[str, str] = {}
    if diff and diff.sensitive_fields_exposed:
        for tier, field_names in diff.sensitive_fields_exposed.items():
            for f in field_names:
                vals = _extract_field_values(attack_response.body, f)
                if vals:
                    masked_sensitive_values[f] = mask_value(str(vals[0]))
                else:
                    masked_sensitive_values[f] = "***REDACTED***"

    resp_diff["masked_sensitive_values"] = masked_sensitive_values
    resp_diff["affected_objects"] = [str(object_id)] if object_id is not None else []

    return Evidence(
        identity=identity_name,
        object_id=str(object_id) if object_id is not None else None,
        expected_status=resolved_expected_status,
        actual_status=attack_response.status,
        request=clean_request,
        baseline_response=clean_baseline_response,
        attack_response=clean_attack_response,
        response_diff=resp_diff,
        timestamp=datetime.now(timezone.utc),
    )


def curl_for_evidence(evidence: Evidence) -> str:
    """Generate a reproducible curl command from an Evidence artifact.

    Args:
        evidence: Technical Evidence model containing request record.

    Returns:
        Shell-safe curl command string with sensitive credentials replaced by $TOKEN.
    """
    return generate_curl(evidence.request)
