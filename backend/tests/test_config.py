"""Unit tests for configuration and target scope enforcement."""

import pytest

from app.config import ScopeViolationError, Settings, assert_in_scope


def test_assert_in_scope_allows_valid_targets() -> None:
    """Ensure allowed targets within scope pass without raising errors."""
    settings = Settings(ALLOWED_HOSTS=["localhost", "127.0.0.1", "target_api"])

    # Target API in container network with port and subpath
    assert_in_scope("http://target_api:9000/x", settings=settings)

    # Localhost with port
    assert_in_scope("http://localhost:8000", settings=settings)

    # Localhost with path and query string
    assert_in_scope("http://localhost:8000/api/v1/users?page=1", settings=settings)

    # IPv4 loopback
    assert_in_scope("https://127.0.0.1:8443/ping", settings=settings)


def test_assert_in_scope_blocks_external_host() -> None:
    """Ensure unlisted external hostnames raise ScopeViolationError."""
    settings = Settings(ALLOWED_HOSTS=["localhost", "127.0.0.1", "target_api"])

    with pytest.raises(ScopeViolationError, match="out of scope"):
        assert_in_scope("https://example.com", settings=settings)


def test_assert_in_scope_blocks_lookalike_domain() -> None:
    """Ensure look-alike or subdomain spoofing raises ScopeViolationError."""
    settings = Settings(ALLOWED_HOSTS=["localhost", "127.0.0.1", "target_api"])

    with pytest.raises(ScopeViolationError, match="out of scope"):
        assert_in_scope("http://target_api.evil.com", settings=settings)

    with pytest.raises(ScopeViolationError, match="out of scope"):
        assert_in_scope("http://localhost.evil.com", settings=settings)


def test_assert_in_scope_blocks_embedded_credentials() -> None:
    """Ensure URLs containing embedded credentials raise ScopeViolationError."""
    settings = Settings(ALLOWED_HOSTS=["localhost", "127.0.0.1", "target_api"])

    with pytest.raises(ScopeViolationError, match="embedded credentials"):
        assert_in_scope("http://user:pass@localhost", settings=settings)

    with pytest.raises(ScopeViolationError, match="embedded credentials"):
        assert_in_scope("http://admin:secret@target_api:9000/api", settings=settings)


def test_assert_in_scope_blocks_disallowed_schemes() -> None:
    """Ensure non-HTTP/HTTPS schemes raise ScopeViolationError."""
    settings = Settings(ALLOWED_HOSTS=["localhost", "127.0.0.1", "target_api"])

    with pytest.raises(ScopeViolationError, match="Scheme 'ftp' is not permitted"):
        assert_in_scope("ftp://localhost", settings=settings)

    with pytest.raises(ScopeViolationError, match="Scheme 'file' is not permitted"):
        assert_in_scope("file:///etc/passwd", settings=settings)


def test_assert_in_scope_blocks_empty_url() -> None:
    """Ensure empty URL raises ScopeViolationError."""
    with pytest.raises(ScopeViolationError, match="cannot be empty"):
        assert_in_scope("")
