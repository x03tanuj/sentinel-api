"""Pydantic schemas for Aegis Secure Cloud API."""

from typing import Any
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., description="Enterprise login username", examples=["userA"])
    password: str = Field(..., description="Account secret password", examples=["passA123"])


class LoginResponse(BaseModel):
    access_token: str = Field(..., description="Signed JSON Web Token")
    token_type: str = Field(default="bearer", description="Token type")
    user_id: int = Field(..., description="User unique identifier")
    role: str = Field(..., description="Enterprise RBAC role")


class UserProfilePublic(BaseModel):
    """Data minimized public profile - No SSN, no credentials, no internal hashes."""
    id: int = Field(..., description="User ID")
    full_name: str = Field(..., description="Full legal name")
    department: str = Field(..., description="Department name")


class UserProfileMe(BaseModel):
    id: int = Field(..., description="User ID")
    username: str = Field(..., description="Login username")
    full_name: str = Field(..., description="Full legal name")
    email: str = Field(..., description="Primary enterprise email")
    department: str = Field(..., description="Department name")
    role: str = Field(..., description="RBAC role")


class DocumentResponse(BaseModel):
    id: int = Field(..., description="Document identifier")
    user_id: int = Field(..., description="Document owner ID")
    title: str = Field(..., description="Document title")
    classification: str = Field(..., description="Data classification level")
    content: str = Field(..., description="Encrypted body contents")
    created_at: str = Field(..., description="Creation ISO timestamp")


class UpdateDocumentRequest(BaseModel):
    title: str | None = Field(default=None, description="Updated document title")
    content: str | None = Field(default=None, description="Updated body content")


class AuditLogResponse(BaseModel):
    id: str = Field(..., description="Audit log entry ID")
    event: str = Field(..., description="Security event category")
    actor: str = Field(..., description="Principal executing event")
    target: str = Field(..., description="Affected resource")
    timestamp: str = Field(..., description="Timestamp")


class HealthResponse(BaseModel):
    status: str = Field(default="ok", description="Service status")
    service: str = Field(default="Aegis Workspace", description="Service name")
    compliance: str = Field(default="SOC2-TypeII", description="Compliance standard")


class ResetResponse(BaseModel):
    status: str = Field(default="reset", description="Reset status")
