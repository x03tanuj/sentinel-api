"""In-memory seed data and persistence for Aegis Secure Cloud API."""

import copy
import hashlib
import time
from typing import Any


def _hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


SEED_USERS: list[dict[str, Any]] = [
    {
        "id": 1,
        "username": "userA",
        "password": "passA123",
        "password_hash": _hash_pw("passA123"),
        "full_name": "Alexander Hayes",
        "email": "alexander.hayes@aegiscloud.internal",
        "department": "Engineering & DevOps",
        "role": "user",
    },
    {
        "id": 2,
        "username": "userB",
        "password": "passB123",
        "password_hash": _hash_pw("passB123"),
        "full_name": "Brianna Chen",
        "email": "brianna.chen@aegiscloud.internal",
        "department": "Product Management",
        "role": "user",
    },
    {
        "id": 3,
        "username": "secadmin",
        "password": "admin123",
        "password_hash": _hash_pw("admin123"),
        "full_name": "Security Operations Administrator",
        "email": "secops@aegiscloud.internal",
        "department": "Global Information Security",
        "role": "admin",
    },
]

SEED_DOCUMENTS: list[dict[str, Any]] = [
    {
        "id": 401,
        "user_id": 1,
        "title": "Architecture Blueprint: Zero-Trust Gateway",
        "classification": "CONFIDENTIAL",
        "content": "Detailed network zoning and mutual TLS topology documentation.",
        "created_at": "2026-08-10T09:00:00Z",
    },
    {
        "id": 402,
        "user_id": 2,
        "title": "Q4 Commercial Product Roadmap & Pricing",
        "classification": "RESTRICTED",
        "content": "Enterprise SKU tiering, margins, and customer rollout schedules.",
        "created_at": "2026-09-01T11:00:00Z",
    },
]

SEED_AUDIT_LOGS: list[dict[str, Any]] = [
    {
        "id": "AUDIT-2026-8812",
        "event": "MFA_POLICY_ENFORCED",
        "actor": "secadmin",
        "target": "Global Policy #1",
        "timestamp": "2026-09-24T12:00:00Z",
    }
]

# In-memory storage
_users: list[dict[str, Any]] = copy.deepcopy(SEED_USERS)
_documents: list[dict[str, Any]] = copy.deepcopy(SEED_DOCUMENTS)
_audit_logs: list[dict[str, Any]] = copy.deepcopy(SEED_AUDIT_LOGS)

# Rate limiting sliding window state: ip -> list of timestamps
_login_attempts: dict[str, list[float]] = {}


def reset_data() -> None:
    global _users, _documents, _audit_logs, _login_attempts
    _users = copy.deepcopy(SEED_USERS)
    _documents = copy.deepcopy(SEED_DOCUMENTS)
    _audit_logs = copy.deepcopy(SEED_AUDIT_LOGS)
    _login_attempts.clear()


def get_users() -> list[dict[str, Any]]:
    return _users


def get_user_by_id(uid: int) -> dict[str, Any] | None:
    return next((u for u in _users if u["id"] == uid), None)


def get_user_by_username(username: str) -> dict[str, Any] | None:
    return next((u for u in _users if u["username"] == username), None)


def get_documents() -> list[dict[str, Any]]:
    return _documents


def get_document_by_id(did: int) -> dict[str, Any] | None:
    return next((d for d in _documents if d["id"] == did), None)


def delete_document(did: int) -> bool:
    global _documents
    for idx, d in enumerate(_documents):
        if d["id"] == did:
            del _documents[idx]
            return True
    return False


def get_audit_logs() -> list[dict[str, Any]]:
    return _audit_logs


def check_rate_limit(key: str, max_requests: int = 15, window_seconds: float = 60.0) -> bool:
    """Return True if allowed, False if limit exceeded."""
    now = time.monotonic()
    attempts = _login_attempts.setdefault(key, [])
    # purge old
    _login_attempts[key] = [t for t in attempts if now - t < window_seconds]
    if len(_login_attempts[key]) >= max_requests:
        return False
    _login_attempts[key].append(now)
    return True
