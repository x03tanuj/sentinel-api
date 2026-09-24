"""Unit tests for the differential analysis engine (pure functions, no network)."""

import json

import pytest

from app.engine.differential import (
    VOLATILE_KEYS,
    classify_field,
    compare,
    flatten,
    is_denied,
    is_not_found,
    is_success,
    summarize_diff_for_evidence,
)
from app.models import Identity, ResponseRecord


def test_classify_field() -> None:
    """Validate word/token matching for field classification and false-positive resistance."""
    assert classify_field("passwordHash") == "SECRET"
    assert classify_field("user_ssn") == "SECRET"
    assert classify_field("api_key") == "SECRET"
    assert classify_field("access_token") == "SECRET"

    assert classify_field("email") == "PERSONAL"
    assert classify_field("phone_number") == "PERSONAL"
    assert classify_field("home_address") == "PERSONAL"

    assert classify_field("role") == "LOW"
    assert classify_field("is_admin") == "LOW"
    assert classify_field("permissions") == "LOW"

    # Critical false-positive checks: substrings must not trigger matches
    assert classify_field("passenger") is None
    assert classify_field("compass") is None
    assert classify_field("pass_through") is None


def test_flatten_drops_volatile_keys() -> None:
    """Validate JSON flattening into dot-notation paths while ignoring volatile headers/timestamps."""
    payload = {
        "id": 101,
        "name": "Widget",
        "created_at": "2026-09-24T12:00:00Z",
        "updated_at": "2026-09-24T12:05:00Z",
        "request_id": "req-xyz-123",
        "etag": "W/\"12345\"",
        "items": [
            {"product_id": 1, "qty": 2, "timestamp": 1234567890},
            {"product_id": 2, "qty": 1},
        ],
    }

    flat = flatten(payload)

    assert flat["id"] == 101
    assert flat["name"] == "Widget"
    assert flat["items.0.product_id"] == 1
    assert flat["items.0.qty"] == 2
    assert flat["items.1.product_id"] == 2

    # Volatile keys must be dropped
    assert "created_at" not in flat
    assert "updated_at" not in flat
    assert "request_id" not in flat
    assert "etag" not in flat
    assert "items.0.timestamp" not in flat


def test_compare_identical_bodies() -> None:
    """Comparing identical response bodies yields similarity 1.0."""
    body = {"id": 101, "owner_id": 1, "status": "shipped"}
    resp1 = ResponseRecord(status=200, headers={}, body=body, size=50, latency_ms=10.0)
    resp2 = ResponseRecord(status=200, headers={}, body=body, size=50, latency_ms=12.0)

    diff = compare(baseline=resp1, attack=resp2)

    assert diff.status_changed is False
    assert diff.baseline_status == 200
    assert diff.attack_status == 200
    assert diff.body_similarity == pytest.approx(1.0)
    assert diff.schema_similarity == pytest.approx(1.0)
    assert diff.attack_body_empty is False
    assert diff.attack_body_is_error is False


def test_compare_different_owners() -> None:
    """Detect when attack response body owner_id differs from attacker identity user_id."""
    victim_body = {"id": 101, "owner_id": 1, "description": "Victim Order"}
    resp = ResponseRecord(status=200, headers={}, body=victim_body, size=60, latency_ms=10.0)
    attacker = Identity(name="userB", role="user", user_id="2")

    diff = compare(baseline=None, attack=resp, attacker=attacker, requested_object_id="101")

    assert diff.same_object_id is True
    assert diff.owner_id_differs is True


def test_soft_fail_200_is_error() -> None:
    """A 200 OK containing only error keys or success=false is classified as attack_body_is_error."""
    resp_err1 = ResponseRecord(
        status=200,
        headers={},
        body={"error": "not found", "detail": "Object does not exist"},
        size=50,
        latency_ms=10.0,
    )
    diff1 = compare(baseline=None, attack=resp_err1)
    assert diff1.attack_body_is_error is True

    resp_err2 = ResponseRecord(
        status=200,
        headers={},
        body={"success": False, "message": "Access denied"},
        size=40,
        latency_ms=10.0,
    )
    diff2 = compare(baseline=None, attack=resp_err2)
    assert diff2.attack_body_is_error is True

    # Real data with message key is not an error
    resp_ok = ResponseRecord(
        status=200,
        headers={},
        body={"id": 1, "name": "Report", "message": "All items processed"},
        size=60,
        latency_ms=10.0,
    )
    diff3 = compare(baseline=None, attack=resp_ok)
    assert diff3.attack_body_is_error is False


def test_empty_body_flags() -> None:
    """Empty bodies ({}, [], None, or size <= 2) flag attack_body_empty True."""
    for empty_body in ({}, [], "", None):
        resp = ResponseRecord(status=200, headers={}, body=empty_body, size=2, latency_ms=5.0)
        diff = compare(baseline=None, attack=resp)
        assert diff.attack_body_empty is True


def test_compare_no_baseline() -> None:
    """Comparison with no baseline yields 0.0 similarities."""
    resp = ResponseRecord(
        status=200,
        headers={},
        body={"id": 105, "item": "gadget"},
        size=30,
        latency_ms=10.0,
    )
    diff = compare(baseline=None, attack=resp, requested_object_id="105")

    assert diff.baseline_status is None
    assert diff.attack_status == 200
    assert diff.body_similarity == 0.0
    assert diff.schema_similarity == 0.0
    assert diff.same_object_id is True


def test_summarize_diff_for_evidence_masks_secrets() -> None:
    """summarize_diff_for_evidence must never expose raw sensitive values like SSN."""
    raw_ssn = "444-55-6666"
    body = {
        "id": 1,
        "username": "userA",
        "ssn": raw_ssn,
        "password_hash": "pbkdf2:sha256:600000$xyz",
    }
    resp = ResponseRecord(status=200, headers={}, body=body, size=80, latency_ms=10.0)
    diff = compare(baseline=None, attack=resp)

    summary = summarize_diff_for_evidence(diff, resp)
    summary_json = json.dumps(summary)

    # Seed SSN and password hash must never appear in cleartext
    assert raw_ssn not in summary_json
    assert "pbkdf2:sha256" not in summary_json
    assert "ssn" in str(summary["sensitive_fields_masked"]["SECRET"])
    assert "password_hash" in str(summary["sensitive_fields_masked"]["SECRET"])


def test_status_helpers() -> None:
    """Helper predicates for status code classification."""
    assert is_success(200) is True
    assert is_success(204) is True
    assert is_success(400) is False

    assert is_denied(401) is True
    assert is_denied(403) is True
    assert is_denied(404) is False

    assert is_not_found(404) is True
    assert is_not_found(200) is False
