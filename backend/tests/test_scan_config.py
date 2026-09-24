"""Unit tests for ScanConfig validation and public view sanitization."""

from __future__ import annotations

import json
import pytest
from pydantic import ValidationError

from app.config import get_settings
from app.engine.identity import IdentityConfig
from app.engine.scanner import ScanConfig


def _valid_identity(name: str = "userA", role: str = "user", password: str = "Secret123!") -> IdentityConfig:
    return IdentityConfig(
        name=name,
        role=role,
        username=f"{name}_user",
        password=password,
        login_path="/auth/login",
    )


def test_scan_config_spec_exclusive() -> None:
    """Exactly one of spec_url or spec_inline must be provided."""
    ident = _valid_identity()

    # Neither provided
    with pytest.raises(ValidationError, match="Exactly one of 'spec_url' or 'spec_inline'"):
        ScanConfig(
            base_url="http://127.0.0.1:9000",
            identities=[ident],
        )

    # Both provided
    with pytest.raises(ValidationError, match="Exactly one of 'spec_url' or 'spec_inline'"):
        ScanConfig(
            spec_url="http://127.0.0.1:9000/openapi.json",
            spec_inline={"openapi": "3.0.0", "paths": {}},
            base_url="http://127.0.0.1:9000",
            identities=[ident],
        )

    # Valid with spec_url
    cfg1 = ScanConfig(
        spec_url="http://127.0.0.1:9000/openapi.json",
        base_url="http://127.0.0.1:9000",
        identities=[ident],
    )
    assert cfg1.spec_url == "http://127.0.0.1:9000/openapi.json"
    assert cfg1.spec_inline is None

    # Valid with spec_inline
    cfg2 = ScanConfig(
        spec_inline={"openapi": "3.0.0", "paths": {}},
        base_url="http://127.0.0.1:9000",
        identities=[ident],
    )
    assert cfg2.spec_inline == {"openapi": "3.0.0", "paths": {}}
    assert cfg2.spec_url is None


def test_scan_config_unknown_check_rejected() -> None:
    """Unknown check names outside the CHECKS registry must be rejected."""
    ident = _valid_identity()
    with pytest.raises(ValidationError, match="Unknown check name"):
        ScanConfig(
            spec_url="http://127.0.0.1:9000/openapi.json",
            base_url="http://127.0.0.1:9000",
            identities=[ident],
            enabled_checks=["bola", "invalid_check_name_xyz"],
        )


def test_scan_config_identities_validation() -> None:
    """Identity name constraints, uniqueness, and anonymous prohibition."""
    # Prohibit 'anonymous'
    with pytest.raises(ValidationError, match="Identity name 'anonymous' is reserved"):
        ScanConfig(
            spec_url="http://127.0.0.1:9000/openapi.json",
            base_url="http://127.0.0.1:9000",
            identities=[_valid_identity(name="anonymous")],
        )

    # Reject duplicate names
    with pytest.raises(ValidationError, match="Duplicate identity name"):
        ScanConfig(
            spec_url="http://127.0.0.1:9000/openapi.json",
            base_url="http://127.0.0.1:9000",
            identities=[_valid_identity(name="userA"), _valid_identity(name="userA")],
        )

    # Reject invalid name pattern (special characters or too long)
    with pytest.raises(ValidationError, match="is invalid. Names must match"):
        ScanConfig(
            spec_url="http://127.0.0.1:9000/openapi.json",
            base_url="http://127.0.0.1:9000",
            identities=[_valid_identity(name="user@bad!name")],
        )

    # Reject more than MAX_IDENTITIES (5)
    too_many = [_valid_identity(name=f"user_{i}") for i in range(6)]
    with pytest.raises(ValidationError, match="exceeds MAX_IDENTITIES"):
        ScanConfig(
            spec_url="http://127.0.0.1:9000/openapi.json",
            base_url="http://127.0.0.1:9000",
            identities=too_many,
        )


def test_scan_config_login_path_validation() -> None:
    """Identity login_path must start with '/'."""
    with pytest.raises(ValidationError, match="login_path must start with '/'"):
        IdentityConfig(
            name="user1",
            role="user",
            login_path="auth/login",  # Missing leading slash
            username="user1",
            password="pwd",
        )


def test_scan_config_budget_caps() -> None:
    """test_case_budget and max_requests must be properly bounded."""
    settings = get_settings()
    ident = _valid_identity()

    # Budget over MAX_TEST_CASE_BUDGET
    with pytest.raises(ValidationError, match="exceeds MAX_TEST_CASE_BUDGET"):
        ScanConfig(
            spec_url="http://127.0.0.1:9000/openapi.json",
            base_url="http://127.0.0.1:9000",
            identities=[ident],
            test_case_budget=settings.MAX_TEST_CASE_BUDGET + 1,
        )

    # max_requests gets capped at MAX_REQUESTS_PER_SCAN
    cfg = ScanConfig(
        spec_url="http://127.0.0.1:9000/openapi.json",
        base_url="http://127.0.0.1:9000",
        identities=[ident],
        max_requests=999999,
    )
    assert cfg.max_requests == settings.MAX_REQUESTS_PER_SCAN


def test_scan_config_size_limits() -> None:
    """Oversized inline spec and sample bodies must be rejected."""
    ident = _valid_identity()

    # Oversized sample body (> 20 KB)
    huge_sample = {"payload": "X" * 25000}
    with pytest.raises(ValidationError, match="exceeds maximum permitted size of 20 KB"):
        ScanConfig(
            spec_url="http://127.0.0.1:9000/openapi.json",
            base_url="http://127.0.0.1:9000",
            identities=[ident],
            sample_bodies={"order": huge_sample},
        )

    # Oversized inline spec (> MAX_SPEC_BYTES)
    settings = get_settings()
    huge_spec = {"info": {"title": "Huge"}, "data": "A" * (settings.MAX_SPEC_BYTES + 100)}
    with pytest.raises(ValidationError, match="exceeds MAX_SPEC_BYTES"):
        ScanConfig(
            spec_inline=huge_spec,
            base_url="http://127.0.0.1:9000",
            identities=[ident],
        )


def test_scan_config_public_view_contains_no_secrets() -> None:
    """public_view() must expose only name/role, never usernames or passwords."""
    sensitive_user = "top_secret_username_999"
    sensitive_pass = "P@ssword!SuperSecret123"

    cfg = ScanConfig(
        spec_url="http://127.0.0.1:9000/openapi.json",
        base_url="http://127.0.0.1:9000",
        identities=[
            IdentityConfig(
                name="alice",
                role="auditor",
                username=sensitive_user,
                password=sensitive_pass,
                login_path="/auth/login",
            )
        ],
    )

    public = cfg.public_view()
    serialized = json.dumps(public)

    # Assert neither the username nor password string appears anywhere
    assert sensitive_user not in serialized
    assert sensitive_pass not in serialized

    # Assert identities only include name and role
    assert public["identities"] == [{"name": "alice", "role": "auditor"}]
    assert public["base_url"] == "http://127.0.0.1:9000"
    assert public["spec_source"] == "url:127.0.0.1:9000"
