"""Unit tests for redaction and value masking logic."""

from app.engine.redaction import mask_value, redact_body, redact_headers, redact_response
from app.models import ResponseRecord


def test_redact_headers_case_insensitive() -> None:
    headers = {
        "Authorization": "Bearer secret_token_12345",
        "COOKIE": "session=abcde12345",
        "Set-Cookie": "tracker=xyz",
        "X-Api-Key": "my-api-key-999",
        "Proxy-Authorization": "Basic dXNlcjpwYXNz",
        "Content-Type": "application/json",
        "X-Custom-Header": "harmless_value",
    }
    redacted = redact_headers(headers)

    assert redacted["Authorization"] == "Bearer ***REDACTED***"
    assert redacted["COOKIE"] == "***REDACTED***"
    assert redacted["Set-Cookie"] == "***REDACTED***"
    assert redacted["X-Api-Key"] == "***REDACTED***"
    assert redacted["Proxy-Authorization"] == "***REDACTED***"
    assert redacted["Content-Type"] == "application/json"
    assert redacted["X-Custom-Header"] == "harmless_value"


def test_redact_headers_without_scheme() -> None:
    headers = {"Authorization": "raw_opaque_token"}
    redacted = redact_headers(headers)
    assert redacted["Authorization"] == "***REDACTED***"


def test_redact_body_nested_structures() -> None:
    payload = {
        "user": {
            "name": "Alice",
            "password": "supersecretpassword",
            "password_hash": "$2b$12$abcdefg",
            "access_token": "token123",
            "api_key": "key999",
            "meta": {
                "secret_info": "classified",
                "normal": "ok",
            },
        },
        "tokens": ["tok1", "tok2"],
        "tags": ["tag1", "tag2"],
        "items": [
            {"id": 1, "name": "Item A", "passwd": "secret_field"},
            {"id": 2, "name": "Item B", "refresh_token": "rt_value"},
        ],
    }

    redacted = redact_body(payload)

    # Validate redactions
    assert redacted["user"]["password"] == "***REDACTED***"
    assert redacted["user"]["password_hash"] == "***REDACTED***"
    assert redacted["user"]["access_token"] == "***REDACTED***"
    assert redacted["user"]["api_key"] == "***REDACTED***"
    assert redacted["user"]["meta"]["secret_info"] == "***REDACTED***"
    assert redacted["tokens"] == "***REDACTED***"
    assert redacted["items"][0]["passwd"] == "***REDACTED***"
    assert redacted["items"][1]["refresh_token"] == "***REDACTED***"

    # Validate harmless fields preserved
    assert redacted["user"]["name"] == "Alice"
    assert redacted["user"]["meta"]["normal"] == "ok"
    assert redacted["items"][0]["name"] == "Item A"
    assert redacted["tags"] == ["tag1", "tag2"]


def test_redact_body_immutability() -> None:
    original = {"password": "mypassword", "info": {"secret": "topsecret"}}
    redacted = redact_body(original)

    # Verify input was not mutated
    assert original["password"] == "mypassword"
    assert original["info"]["secret"] == "topsecret"
    assert redacted["password"] == "***REDACTED***"
    assert redacted["info"]["secret"] == "***REDACTED***"


def test_mask_value() -> None:
    assert mask_value("11000000033") == "11*******33"
    assert mask_value("12345") == "12*45"
    assert mask_value("1234") == "****"
    assert mask_value("ab") == "**"
    assert mask_value("") == ""


def test_redact_response() -> None:
    raw_resp = ResponseRecord(
        status=200,
        headers={"Authorization": "Bearer secret", "Content-Type": "application/json"},
        body={"username": "bob", "password_hash": "hash123"},
        size=150,
        latency_ms=12.5,
    )
    redacted_resp = redact_response(raw_resp)

    assert redacted_resp.status == 200
    assert redacted_resp.headers["Authorization"] == "Bearer ***REDACTED***"
    assert redacted_resp.headers["Content-Type"] == "application/json"
    assert redacted_resp.body["username"] == "bob"
    assert redacted_resp.body["password_hash"] == "***REDACTED***"
    assert redacted_resp.size == 150
    assert redacted_resp.latency_ms == 12.5

    # Original remains untouched
    assert raw_resp.headers["Authorization"] == "Bearer secret"
    assert raw_resp.body["password_hash"] == "hash123"
