"""Redaction utilities for scrubbed auditing, logging, and evidence generation.

Guarantees that sensitive headers, secrets, bearer tokens, and credentials
are sanitized before data is displayed, serialized, or sent to external systems.
"""

from collections.abc import Mapping
import copy
import re
from typing import Any

from app.models import ResponseRecord

SENSITIVE_HEADER_NAMES: set[str] = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
}

SENSITIVE_KEY_PATTERN: re.Pattern = re.compile(
    r"password|passwd|token|access_token|refresh_token|secret|api_?key|authorization",
    re.IGNORECASE,
)


def redact_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    """Redact sensitive HTTP headers while preserving header structure and auth schemes.

    Args:
        headers: Mapping of HTTP header names to values.

    Returns:
        New dictionary with sensitive values scrubbed.
    """
    if not headers:
        return {}

    redacted: dict[str, str] = {}
    for key, val in headers.items():
        str_val = str(val) if val is not None else ""
        lower_key = str(key).strip().lower()

        if lower_key in SENSITIVE_HEADER_NAMES:
            if lower_key == "authorization":
                # Preserve scheme (e.g. Bearer, Basic) if present
                if " " in str_val:
                    scheme, _ = str_val.split(" ", 1)
                    redacted[str(key)] = f"{scheme} ***REDACTED***"
                else:
                    redacted[str(key)] = "***REDACTED***"
            else:
                redacted[str(key)] = "***REDACTED***"
        else:
            redacted[str(key)] = str_val

    return redacted


def redact_body(body: Any) -> Any:
    """Recursively redact sensitive key-values from dicts and lists without mutating input.

    Args:
        body: Payload object (dict, list, primitive, or None).

    Returns:
        Deep-copied data structure with sensitive fields replaced by '***REDACTED***'.
    """
    if isinstance(body, dict):
        new_dict: dict[str, Any] = {}
        for k, v in body.items():
            if SENSITIVE_KEY_PATTERN.search(str(k)):
                new_dict[k] = "***REDACTED***"
            else:
                new_dict[k] = redact_body(v)
        return new_dict
    elif isinstance(body, list):
        return [redact_body(item) for item in body]
    return body


def redact_response(resp: ResponseRecord) -> ResponseRecord:
    """Return a sanitized copy of a ResponseRecord with headers and body scrubbed.

    Note:
        The raw ResponseRecord is kept in memory during scanning for technical analysis
        (e.g. detecting exposed password_hash or sensitive field leaks). Anything shown
        to users, printed in logs, persisted to disk, or sent to an LLM must pass through
        redaction or masking first.

    Args:
        resp: Original ResponseRecord.

    Returns:
        Sanitized ResponseRecord copy.
    """
    return ResponseRecord(
        status=resp.status,
        headers=redact_headers(resp.headers),
        body=redact_body(resp.body),
        size=resp.size,
        latency_ms=resp.latency_ms,
    )


def mask_value(v: str) -> str:
    """Mask a string value preserving only the first 2 and last 2 characters.

    Example:
        mask_value("11000000033") -> "11*******33"

    Args:
        v: Sensitive string to mask.

    Returns:
        Partially masked string suitable for security evidence reporting.
    """
    if not v:
        return ""
    if len(v) <= 4:
        return "*" * len(v)
    return f"{v[:2]}{'*' * (len(v) - 4)}{v[-2:]}"
