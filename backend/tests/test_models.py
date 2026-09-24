"""Unit tests for SentinelAPI data models and safety serialization."""

import pytest
from pydantic import ValidationError

from app.models import (
    Endpoint,
    Evidence,
    Finding,
    Identity,
    RequestRecord,
    ResponseRecord,
    Severity,
)


def test_severity_enum_values() -> None:
    """Ensure all required Severity enum levels are present and match string values."""
    assert Severity.CRITICAL == "CRITICAL"
    assert Severity.HIGH == "HIGH"
    assert Severity.MEDIUM == "MEDIUM"
    assert Severity.LOW == "LOW"
    assert Severity.INFO == "INFO"

    all_severities = {s.value for s in Severity}
    assert all_severities == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def test_confidence_validation_rejects_out_of_range() -> None:
    """Ensure Finding validates that confidence is between 0.0 and 1.0."""
    # Confidence > 1.0 should raise ValidationError
    with pytest.raises(ValidationError):
        Finding(
            check="BOLA_01",
            endpoint="/api/users/{id}",
            method="GET",
            title="Broken Object Level Authorization",
            severity=Severity.HIGH,
            confidence=1.5,
            explanation="Unauthenticated access to arbitrary user object.",
            curl_poc="curl http://target_api/api/users/2",
            fix_hint="Enforce object-level authorization checks.",
        )

    # Confidence < 0.0 should raise ValidationError
    with pytest.raises(ValidationError):
        Finding(
            check="BOLA_01",
            endpoint="/api/users/{id}",
            method="GET",
            title="Broken Object Level Authorization",
            severity=Severity.HIGH,
            confidence=-0.1,
            explanation="Unauthenticated access to arbitrary user object.",
            curl_poc="curl http://target_api/api/users/2",
            fix_hint="Enforce object-level authorization checks.",
        )

    # Valid confidence between 0.0 and 1.0
    finding = Finding(
        check="BOLA_01",
        endpoint="/api/users/{id}",
        method="GET",
        title="Broken Object Level Authorization",
        severity=Severity.HIGH,
        confidence=0.95,
        explanation="Unauthenticated access to arbitrary user object.",
        curl_poc="curl http://target_api/api/users/2",
        fix_hint="Enforce object-level authorization checks.",
    )
    assert finding.confidence == 0.95


def test_identity_token_not_present_in_model_dump_and_repr() -> None:
    """Ensure Identity token is completely excluded from serialization and string representation."""
    secret = "super-secret-bearer-token-12345"
    identity = Identity(
        name="attacker_identity",
        role="attacker",
        token=secret,
        user_id="victim_42",
    )

    # token attribute accessible on instance
    assert identity.token == secret

    # token excluded from model_dump()
    dumped = identity.model_dump()
    assert "token" not in dumped

    # token excluded from repr()
    assert secret not in repr(identity)
    assert "token" not in repr(identity)


def test_evidence_sanitizes_token_and_password() -> None:
    """Ensure Evidence serialization guarantees no field named token or password is ever serialized."""
    evidence = Evidence(
        identity="victim_identity",
        object_id="user_999",
        expected_status=403,
        actual_status=200,
        request=RequestRecord(
            method="GET",
            url="http://target_api:9000/users/999",
            headers_redacted={"Authorization": "Bearer [REDACTED]"},
            body={"token": "leak_attempt_token", "password": "secret_password", "data": "visible"},
        ),
        attack_response=ResponseRecord(
            status=200,
            headers={"Content-Type": "application/json"},
            body={"token": "resp_token", "password": "resp_password", "id": 999},
            size=120,
            latency_ms=12.5,
        ),
        response_diff={"added": ["token", "password"]},
    )

    serialized = evidence.model_dump()

    # Verify no field named 'token' or 'password' exists at any level in serialized dictionary
    def assert_no_sensitive_keys(d: object) -> None:
        if isinstance(d, dict):
            for k, v in d.items():
                assert k.lower() not in ("token", "password"), f"Found forbidden key {k} in serialized Evidence"
                assert_no_sensitive_keys(v)
        elif isinstance(d, list):
            for item in d:
                assert_no_sensitive_keys(item)

    assert_no_sensitive_keys(serialized)
    assert serialized["request"]["body"] == {"data": "visible"}
    assert serialized["attack_response"]["body"] == {"id": 999}


def test_finding_to_dict_works() -> None:
    """Ensure Finding.to_dict() returns serialized dictionary with expected values."""
    finding = Finding(
        check="BFLA_01",
        endpoint="/api/admin/users",
        method="DELETE",
        title="Broken Function Level Authorization",
        severity=Severity.CRITICAL,
        confidence=1.0,
        explanation="Regular user can invoke administrative user deletion.",
        curl_poc="curl -X DELETE http://target_api/api/admin/users",
        fix_hint="Enforce RBAC role checking on admin routes.",
        owasp_id="API5:2023",
    )

    finding_dict = finding.to_dict()

    assert isinstance(finding_dict, dict)
    assert finding_dict["check"] == "BFLA_01"
    assert finding_dict["endpoint"] == "/api/admin/users"
    assert finding_dict["method"] == "DELETE"
    assert finding_dict["severity"] == "CRITICAL"
    assert finding_dict["confidence"] == 1.0
    assert finding_dict["owasp_id"] == "API5:2023"
    assert "id" in finding_dict
    assert "timestamp" in finding_dict


def test_endpoint_model_instantiation() -> None:
    """Ensure Endpoint model fields and defaults behave properly."""
    endpoint = Endpoint(
        method="GET",
        path="/api/items/{item_id}",
        is_object_level=True,
        path_params=["item_id"],
    )
    assert endpoint.method == "GET"
    assert endpoint.is_object_level is True
    assert endpoint.path_params == ["item_id"]
    assert endpoint.query_params == []
    assert endpoint.requires_auth is False
