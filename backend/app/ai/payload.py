"""Secure egress boundary for AI analyst payloads.

SECURITY BOUNDARY: This module defines exactly what data leaves the machine.
Nothing else from the scanner's internal state is ever sent to an LLM.

Allowed outbound fields:
  - check name, OWASP id
  - HTTP method, path TEMPLATE (never real URLs or IDs)
  - severity, confidence, risk_score
  - four component names with their point values
  - attacker identity ROLE (not username)
  - expected vs actual status codes
  - changed and leaked FIELD NAMES with sensitivity tier
  - declared-vs-undeclared field names
  - reproduction summary ("2 of 2")
  - existing fix_hint and explanation
  - framework hint

Never outbound:
  - host names, real URLs, curl commands
  - headers, tokens, passwords, usernames
  - response bodies, masked or raw values
  - object IDs from real data (replaced with "<object-id>")
  - request/response records
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.models import Finding

logger = logging.getLogger(__name__)

# Allowlist of valid framework hints (language-neutral pseudocode when "generic")
FRAMEWORK_HINTS: frozenset[str] = frozenset(
    ["generic", "fastapi", "express", "django", "flask", "spring", "rails", "laravel", "dotnet"]
)

# Patterns that must never appear in an outbound payload
_PATTERN_JWT = re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PATTERN_BEARER = re.compile(r"Bearer\s+", re.IGNORECASE)
_PATTERN_PASSWORD_VALUE = re.compile(r"(?:password|token)\s*[:=]\s*\S+", re.IGNORECASE)
_PATTERN_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PATTERN_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PATTERN_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_PATTERN_URL = re.compile(
    r"https?://[^\s\"'<>]+"
    r"|(?:ftp|ws|wss)://[^\s\"'<>]+",
    re.IGNORECASE,
)
_PATTERN_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
# Object-ID-like patterns (UUIDs, long hex strings, long numeric IDs)
_PATTERN_OBJECT_ID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
    r"|\b[0-9a-f]{24,}\b"
    r"|\b\d{8,}\b",
    re.IGNORECASE,
)


class PayloadNotSafeError(ValueError):
    """Raised when the serialized LLM payload fails the safety assertion."""


def build_llm_payload(finding: Finding, framework_hint: str) -> dict[str, Any]:
    """Build the minimal, sanitized payload that may be sent to an LLM.

    Contains only structural metadata – never secrets, bodies, or real IDs.

    Args:
        finding: The fully resolved Finding from the scanner.
        framework_hint: One of the FRAMEWORK_HINTS allowlist values.

    Returns:
        A flat dict safe to serialize and send to any LLM provider.

    Raises:
        ValueError: If framework_hint is not in the allowlist.
    """
    if framework_hint not in FRAMEWORK_HINTS:
        raise ValueError(
            f"framework_hint '{framework_hint}' is not in the allowlist: {sorted(FRAMEWORK_HINTS)}"
        )

    evidence = finding.evidence
    diff: dict[str, Any] = {}
    attacker_role: str = "unknown"
    expected_status: int | None = None
    actual_status: int | None = None
    changed_fields: list[dict[str, Any]] = []
    leaked_fields: list[dict[str, Any]] = []
    declared_fields: list[str] = []
    undeclared_fields: list[str] = []
    reproduction_result: str = "not reproduced"
    risk_components: dict[str, int] = {}

    if evidence:
        attacker_role = evidence.identity  # identity is role name, not username
        expected_status = evidence.expected_status
        actual_status = evidence.actual_status
        diff = evidence.response_diff or {}

        # Extract field names only (never values)
        for sf in diff.get("sensitive_fields_exposed", []):
            if isinstance(sf, dict):
                leaked_fields.append({
                    "field": sf.get("field", ""),
                    "sensitivity": sf.get("sensitivity", ""),
                })
            elif isinstance(sf, str):
                leaked_fields.append({"field": sf, "sensitivity": "unknown"})

        # Changed field names (structure delta)
        changed_fields = [
            {"field": k}
            for k in diff.get("changed_keys", [])
            if isinstance(k, str)
        ]

        # Declared vs undeclared from schema diff
        schema_fields = diff.get("schema_fields", {})
        declared_fields = [str(f) for f in schema_fields.get("declared", [])]
        undeclared_fields = [str(f) for f in schema_fields.get("undeclared", [])]

        # Reproduction summary: "N of M"
        repro_count = diff.get("reproduction_count", 0)
        repro_attempts = diff.get("reproduction_attempts", 0)
        if repro_attempts:
            reproduction_result = f"{repro_count} of {repro_attempts}"

        # Risk component scores from response_diff
        risk_breakdown = diff.get("risk_breakdown", {})
        if isinstance(risk_breakdown, dict):
            risk_components = {
                k: int(v)
                for k, v in risk_breakdown.items()
                if isinstance(v, (int, float))
            }

    # Sanitize path: replace any real object IDs with placeholder
    path_template = _redact_object_ids(finding.endpoint)

    return {
        "check": finding.check,
        "owasp_id": finding.owasp_id,
        "method": finding.method,
        "path_template": path_template,
        "severity": finding.severity.value if finding.severity else None,
        "confidence": round(finding.confidence, 3),
        "risk_score": risk_components,
        "attacker_role": attacker_role,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "changed_field_names": changed_fields,
        "leaked_field_names": leaked_fields,
        "declared_vs_undeclared": {
            "declared": declared_fields,
            "undeclared": undeclared_fields,
        },
        "reproduction_result": reproduction_result,
        "fix_hint": finding.fix_hint,
        "template_explanation": finding.explanation,
        "framework_hint": framework_hint,
    }


def _redact_object_ids(path: str) -> str:
    """Replace concrete object IDs in a path with the generic placeholder.

    Paths that are already templated (e.g. /orders/{id}) are unchanged.
    Paths with concrete IDs (e.g. /orders/12345) get the ID replaced.
    """
    # If already templated, return as-is
    if "{" in path and "}" in path:
        return path
    # Replace UUID, hex, long-numeric segments
    return _PATTERN_OBJECT_ID.sub("<object-id>", path)


def assert_payload_safe(serialized: str) -> None:
    """Assert the serialized payload contains no sensitive data.

    Raises PayloadNotSafeError immediately on first violation. Callers
    must NOT make the LLM call if this raises. The exception message
    names the pattern category, never the matched value.

    Args:
        serialized: JSON-encoded payload string.

    Raises:
        PayloadNotSafeError: If any forbidden pattern is found.
    """
    checks: list[tuple[re.Pattern[str], str]] = [
        (_PATTERN_JWT, "JWT-shaped token"),
        (_PATTERN_BEARER, "Bearer token prefix"),
        (_PATTERN_PASSWORD_VALUE, "password/token value"),
        (_PATTERN_SSN, "SSN pattern"),
        (_PATTERN_EMAIL, "email address"),
        (_PATTERN_CARD, "card-number-like digit run"),
        (_PATTERN_URL, "URL"),
        (_PATTERN_IP, "IP address"),
    ]
    for pattern, label in checks:
        if pattern.search(serialized):
            logger.warning("Payload safety assertion tripped: %s detected", label)
            raise PayloadNotSafeError(
                f"Payload safety assertion failed: {label} detected. "
                "Falling back to template analysis."
            )
