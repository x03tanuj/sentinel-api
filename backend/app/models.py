"""Domain data models for SentinelAPI scanner.

Defines core models for endpoints, identities, request/response records,
vulnerability evidence, and security findings with strict redaction guarantees.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import (
    BaseModel,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
)


class Severity(str, Enum):
    """Vulnerability severity levels aligned with common security standards."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Endpoint(BaseModel):
    """Represents an API endpoint parsed from an OpenAPI specification."""

    method: str = Field(..., description="HTTP method in uppercase, e.g. GET, POST")
    path: str = Field(..., description="API route path template, e.g. /api/users/{id}")
    operation_id: str | None = Field(default=None, description="Unique OpenAPI operation identifier")
    requires_auth: bool = Field(default=False, description="Indicates whether authentication is required")
    path_params: list[str] = Field(default_factory=list, description="List of parameter names in URL path")
    query_params: list[str] = Field(default_factory=list, description="List of URL query parameter names")
    body_schema: dict[str, Any] | None = Field(default=None, description="Request body JSON schema definition")
    response_schema: dict[str, Any] | None = Field(default=None, description="Response body JSON schema definition")
    resource: str | None = Field(default=None, description="Inferred resource category, e.g. user, account")
    is_object_level: bool = Field(default=False, description="Indicates if endpoint acts on specific object ID")
    is_privileged: bool = Field(default=False, description="Indicates if endpoint requires administrative role")
    tags: list[str] = Field(default_factory=list, description="Categorical tags from specification")
    summary: str = Field(default="", description="Short summary or description from specification")
    hint_source: str | None = Field(default=None, description="If 'llm', this endpoint's flags were augmented by AI hints")


class Identity(BaseModel):
    """Represents a test identity with associated authentication credentials."""

    name: str = Field(..., description="Descriptive identifier for the test actor, e.g. admin_user")
    role: str = Field(..., description="Permission role, e.g. admin, regular_user, anonymous")
    token: str | None = Field(
        default=None,
        repr=False,
        exclude=True,
        description="Authentication bearer token or secret; strictly excluded from serialization and repr",
    )
    user_id: str | int | None = Field(default=None, description="Unique subject or user identifier")


class RequestRecord(BaseModel):
    """Audit record of an outgoing HTTP probe request."""

    method: str = Field(..., description="HTTP method executed")
    url: str = Field(..., description="Full target URL probed")
    headers_redacted: dict[str, str] = Field(default_factory=dict, description="Request headers with sensitive values scrubbed")
    body: dict[str, Any] | str | None = Field(default=None, description="Probe request payload if applicable")


class ResponseRecord(BaseModel):
    """Audit record of an incoming HTTP probe response."""

    status: int = Field(..., description="HTTP response status code")
    headers: dict[str, str] = Field(default_factory=dict, description="HTTP response headers")
    body: Any = Field(default=None, description="Parsed response body payload")
    size: int = Field(default=0, description="Payload size in bytes")
    latency_ms: float = Field(default=0.0, description="Response roundtrip latency in milliseconds")


def _sanitize_no_token_or_password(data: Any) -> Any:
    """Recursively sanitize data structures to guarantee no field named token or password exists."""
    if isinstance(data, dict):
        return {
            k: _sanitize_no_token_or_password(v)
            for k, v in data.items()
            if k.lower() not in ("token", "password")
        }
    if isinstance(data, list):
        return [_sanitize_no_token_or_password(item) for item in data]
    return data


class Evidence(BaseModel):
    """Evidence artifact capturing attack execution and discrepancy against baseline."""

    identity: str = Field(..., description="Test identity utilized during probe")
    object_id: str | None = Field(default=None, description="Target object identifier probed")
    expected_status: int | None = Field(default=None, description="Expected authorization HTTP status code")
    actual_status: int = Field(..., description="Actual HTTP status code received")
    request: RequestRecord = Field(..., description="Probe request details")
    baseline_response: ResponseRecord | None = Field(default=None, description="Legitimate baseline response if captured")
    attack_response: ResponseRecord = Field(..., description="Response captured during attack probe")
    response_diff: dict[str, Any] = Field(default_factory=dict, description="Structural difference between responses")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when evidence was collected",
    )

    @model_serializer(mode="wrap")
    def _serialize_evidence(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """Guarantee no field named token or password is ever serialized in Evidence."""
        raw = handler(self)
        if isinstance(raw, dict):
            return _sanitize_no_token_or_password(raw)
        return raw


class Finding(BaseModel):
    """Security vulnerability finding discovered by a check engine."""

    id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique UUID string identifying finding",
    )
    check: str = Field(..., description="Identifier of security check rule that triggered finding")
    endpoint: str = Field(..., description="API endpoint path where flaw was detected")
    method: str = Field(..., description="HTTP method of vulnerable endpoint")
    title: str = Field(..., description="Concise human-readable vulnerability summary")
    severity: Severity = Field(..., description="Calculated severity rating")
    confidence: float = Field(..., description="Confidence score between 0.0 and 1.0")
    explanation: str = Field(..., description="Detailed explanation of the security flaw")
    evidence: Evidence | None = Field(default=None, description="Technical evidence capturing the vulnerability")
    curl_poc: str = Field(..., description="Reproducible curl command demonstrating the issue")
    fix_hint: str = Field(..., description="Remediation guidance for developers")
    owasp_id: str | None = Field(default=None, description="OWASP API Security Top 10 identifier, e.g. API1:2023")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when finding was created",
    )

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Validate confidence score strictly resides between 0.0 and 1.0."""
        if not (0.0 <= v <= 1.0):
            raise ValueError(f"Confidence score must be between 0.0 and 1.0, got {v}")
        return v

    ai_analysis: dict[str, Any] | None = Field(
        default=None,
        description="AI-generated analysis attached after scan (never changes severity/confidence)",
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert finding model to a serialized dictionary representation."""
        return self.model_dump(mode="json")
