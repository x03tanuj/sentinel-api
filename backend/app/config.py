"""Configuration and security boundary scope enforcement for SentinelAPI.

Manages application settings loaded from environment variables and strictly
enforces scope boundaries to prevent out-of-scope requests or target spoofing.
"""

import json
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


from app.engine.errors import ScopeViolationError, SentinelError


class Settings(BaseSettings):
    """Application configuration settings loaded from environment or defaults."""

    ALLOWED_HOSTS: list[str] = Field(
        default=["localhost", "127.0.0.1", "target_api"],
        description="Explicit allowlist of permitted scan target hostnames",
    )
    REQUEST_TIMEOUT: float = Field(
        default=10.0,
        description="Maximum timeout in seconds for target HTTP requests",
    )
    MAX_RPS: int = Field(
        default=20,
        description="Maximum requests per second allowed per scan probe",
    )
    RATE_LIMIT_PROBE_COUNT: int = Field(
        default=40,
        description="Number of rapid probes sent during rate-limiting checks",
    )
    MAX_REQUESTS_PER_SCAN: int = Field(
        default=1000,
        description="Global hard cap on total HTTP requests executed per scan",
    )
    MAX_RESPONSE_BYTES: int = Field(
        default=2_000_000,
        description="Maximum response size in bytes before stream truncation",
    )
    LLM_PROVIDER: str = Field(
        default="groq",
        description="LLM provider name for finding explanation synthesis",
    )
    LLM_API_KEY: str = Field(
        default="",
        description="API key for LLM provider",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, value: Any) -> list[str]:
        """Parse ALLOWED_HOSTS from list, JSON string, or comma-separated string."""
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("[") and value.endswith("]"):
                try:
                    parsed = json.loads(value)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed]
                except Exception:
                    pass
            return [h.strip() for h in value.split(",") if h.strip()]
        if isinstance(value, (list, set, tuple)):
            return [str(h).strip() for h in value]
        return value


@lru_cache
def get_settings() -> Settings:
    """Retrieve cached application settings instance."""
    return Settings()


def assert_in_scope(url: str, settings: Settings | None = None) -> None:
    """Assert that a target URL is strictly within the allowed scan scope.

    Validates that:
    1. Scheme is strictly 'http' or 'https'.
    2. URL contains no embedded user credentials (e.g. user:pass@host).
    3. Hostname is present and exactly matches an entry in ALLOWED_HOSTS.
       Disallows look-alike hosts such as 'target_api.evil.com'.

    Args:
        url: Full URL string to validate.
        settings: Optional Settings instance; uses cached settings if None.

    Raises:
        ScopeViolationError: If the URL fails any security or scope constraints.
    """
    if not url:
        raise ScopeViolationError("Target URL cannot be empty.")

    active_settings = settings or get_settings()
    parsed = urlparse(url)

    # 1. Scheme validation
    if parsed.scheme.lower() not in ("http", "https"):
        raise ScopeViolationError(
            f"Scheme '{parsed.scheme}' is not permitted. Only 'http' and 'https' are allowed."
        )

    # 2. Reject credentials in URL
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        raise ScopeViolationError(
            "URLs with embedded credentials (user:pass@host) are strictly forbidden."
        )

    # 3. Hostname extraction and validation
    hostname = parsed.hostname
    if not hostname:
        raise ScopeViolationError(f"Could not extract a valid hostname from URL: {url}")

    hostname_clean = hostname.strip().lower()
    allowed_hosts_clean = {h.strip().lower() for h in active_settings.ALLOWED_HOSTS}

    if hostname_clean not in allowed_hosts_clean:
        raise ScopeViolationError(
            f"Target host '{hostname}' is out of scope. Allowed hosts: {list(allowed_hosts_clean)}"
        )
