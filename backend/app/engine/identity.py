"""Test identity manager and credential authentication engine for SentinelAPI.

Handles authenticated sessions across test personas (e.g. userA, userB, admin, anonymous),
extracting subject IDs and roles from JWTs without persisting tokens to disk.
"""

from typing import Any

import jwt
from pydantic import BaseModel, Field, SecretStr

from app.engine.errors import IdentityNotFoundError, LoginFailedError
from app.engine.http_executor import Executor
from app.models import Identity

ANONYMOUS: Identity = Identity(
    name="anonymous",
    role="anonymous",
    token=None,
    user_id=None,
)


class IdentityConfig(BaseModel):
    """Configuration specification for a test identity persona."""

    name: str = Field(..., description="Unique persona name (e.g. userA, admin)")
    role: str = Field(default="user", description="Default role if not specified in JWT claims")
    username: str = Field(..., description="Login username or identifier")
    password: SecretStr = Field(..., description="Login password strictly protected as SecretStr")
    login_path: str = Field(default="/auth/login", description="Authentication endpoint path")
    token_key: str = Field(default="access_token", description="JSON response key containing token")
    username_field: str = Field(default="username", description="Form field or JSON key for username")
    password_field: str = Field(default="password", description="Form field or JSON key for password")


class IdentityManager:
    """Manages active authenticated test identities in memory during a scan run."""

    def __init__(self, base_url: str, executor: Executor) -> None:
        """Initialize IdentityManager for a specific target base URL and executor.

        Args:
            base_url: Base URL of the target API.
            executor: Configured Executor instance used for network requests.
        """
        self.base_url = base_url.rstrip("/")
        self.executor = executor
        self._identities: dict[str, Identity] = {"anonymous": ANONYMOUS}

    def __repr__(self) -> str:
        return f"IdentityManager(base_url={self.base_url!r}, identities={list(self._identities.keys())!r})"

    def __str__(self) -> str:
        return self.__repr__()

    async def login(self, cfg: IdentityConfig) -> Identity:
        """Authenticate an identity against the target and register its active session.

        Extracts user_id (from JWT 'sub' claim) and role without verifying signatures,
        falling back to default roles for opaque tokens. Raw login response bodies
        and password values are never retained in memory or logged.

        Args:
            cfg: IdentityConfig containing persona credentials.

        Returns:
            Registered Identity instance.

        Raises:
            LoginFailedError: If the target rejects the credentials or returns non-2xx status.
        """
        login_url = f"{self.base_url}{cfg.login_path}"
        payload = {
            cfg.username_field: cfg.username,
            cfg.password_field: cfg.password.get_secret_value(),
        }

        try:
            _, resp_rec = await self.executor.execute(
                method="POST",
                url=login_url,
                identity=None,
                json_body=payload,
            )
        except Exception as exc:
            raise LoginFailedError(
                f"Authentication failed for identity '{cfg.name}': {type(exc).__name__}"
            ) from None

        if resp_rec.status < 200 or resp_rec.status >= 300:
            status = resp_rec.status
            del resp_rec
            raise LoginFailedError(f"Authentication failed for identity '{cfg.name}' with status {status}")

        if not isinstance(resp_rec.body, dict) or cfg.token_key not in resp_rec.body:
            del resp_rec
            raise LoginFailedError(
                f"Authentication failed for identity '{cfg.name}': token key '{cfg.token_key}' missing from response"
            )

        token = str(resp_rec.body[cfg.token_key])
        del resp_rec  # immediately discard raw login response

        # Decode JWT claims without signature verification
        user_id: str | int | None = None
        role = cfg.role
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
            sub = claims.get("sub")
            if sub is not None:
                user_id = str(sub)
            if "role" in claims and claims["role"]:
                role = str(claims["role"])
        except Exception:
            # Opaque token or unparseable claims
            user_id = None

        identity = Identity(
            name=cfg.name,
            role=role,
            token=token,
            user_id=user_id,
        )
        self._identities[cfg.name] = identity
        return identity

    async def login_all(self, configs: list[IdentityConfig]) -> list[Identity]:
        """Authenticate multiple identities sequentially and return successfully registered list.

        Args:
            configs: List of IdentityConfig objects to authenticate.

        Returns:
            List of registered Identity objects.

        Raises:
            LoginFailedError: Aggregate error listing names of all failed identities.
        """
        failures: list[str] = []
        identities: list[Identity] = []

        for cfg in configs:
            try:
                ident = await self.login(cfg)
                identities.append(ident)
            except LoginFailedError:
                failures.append(cfg.name)

        if failures:
            raise LoginFailedError(f"Authentication failed for identities: {', '.join(failures)}")

        return identities

    def get(self, name: str) -> Identity:
        """Retrieve an identity by name. 'anonymous' always resolves.

        Args:
            name: Identity identifier.

        Returns:
            Resolved Identity instance.

        Raises:
            IdentityNotFoundError: If the identity has not been registered.
        """
        if name in self._identities:
            return self._identities[name]
        raise IdentityNotFoundError(
            f"Identity '{name}' not found. Registered identities: {list(self._identities.keys())}"
        )

    def all(self) -> list[Identity]:
        """Return all registered non-anonymous identities."""
        return [ident for name, ident in self._identities.items() if name != "anonymous"]

    def names(self) -> list[str]:
        """Return list of all registered identity names including anonymous."""
        return list(self._identities.keys())

    def owners_of_role(self, role: str) -> list[Identity]:
        """Return all registered identities matching the given role."""
        return [ident for ident in self._identities.values() if ident.role == role]

    def list_identities(self) -> list[Identity]:
        """Return list of all registered identities including anonymous."""
        return list(self._identities.values())
