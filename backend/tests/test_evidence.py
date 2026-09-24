"""Unit tests for structured Evidence builder and defense-in-depth sanitization."""

import json

import pytest

from app.engine.differential import DiffResult
from app.engine.evidence import build_evidence, curl_for_evidence
from app.engine.http_executor import generate_curl
from app.models import RequestRecord, ResponseRecord


def test_build_evidence_defense_in_depth_redaction() -> None:
    """Verify build_evidence scrubs raw tokens, headers, and secrets even from dirty inputs."""
    dirty_request = RequestRecord(
        method="GET",
        url="http://localhost:9000/orders/101",
        headers_redacted={
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecrettoken",
            "Cookie": "session_id=secretcookie12345",
            "X-Api-Key": "apikey-abcdef123456",
        },
        body={"password": "MySuperSecretPassword123!", "ssn": "444-55-6666"},
    )

    dirty_attack_resp = ResponseRecord(
        status=200,
        headers={"Authorization": "Bearer response_secret_token"},
        body={
            "password_hash": "$2b$12$superSecretHashValue12345",
            "ssn": "444-55-6666",
            "user_id": 101,
        },
        size=150,
    )

    diff = DiffResult(
        status_changed=False,
        baseline_status=200,
        attack_status=200,
        body_similarity=0.9,
        schema_similarity=1.0,
        same_object_id=True,
        owner_id_differs=True,
        sensitive_fields_exposed={"SECRET": ["password_hash", "ssn"]},
        size_ratio=1.0,
        changed_fields=[],
        attack_body_empty=False,
        attack_body_is_error=False,
    )

    evidence = build_evidence(
        case_result_or_context=None,
        request=dirty_request,
        baseline_response=None,
        attack_response=dirty_attack_resp,
        diff=diff,
        identity="userA",
        object_id="101",
        expected_status=403,
    )

    serialized = json.dumps(evidence.model_dump(mode="json"))

    # Assert raw tokens, passwords, hashes, and SSNs never leak into serialized Evidence
    assert "supersecrettoken" not in serialized
    assert "secretcookie12345" not in serialized
    assert "apikey-abcdef123456" not in serialized
    assert "MySuperSecretPassword123!" not in serialized
    assert "$2b$12$superSecretHashValue12345" not in serialized
    assert "444-55-6666" not in serialized

    # Check that masked_sensitive_values exists in response_diff
    assert "masked_sensitive_values" in evidence.response_diff
    assert "affected_objects" in evidence.response_diff
    assert evidence.response_diff["affected_objects"] == ["101"]


def test_curl_for_evidence_matches_generate_curl() -> None:
    """Verify curl_for_evidence matches generate_curl output exactly."""
    req = RequestRecord(
        method="GET",
        url="http://localhost:9000/api/resource/42",
        headers_redacted={"Authorization": "Bearer ***REDACTED***"},
        body=None,
    )
    resp = ResponseRecord(status=200, body={"ok": True})
    evidence = build_evidence(
        case_result_or_context=None,
        request=req,
        baseline_response=None,
        attack_response=resp,
        diff=None,
        identity="userA",
        object_id="42",
        expected_status=403,
    )

    curl_cmd = curl_for_evidence(evidence)
    expected_curl = generate_curl(evidence.request)
    assert curl_cmd == expected_curl
    assert "$TOKEN" in curl_cmd
