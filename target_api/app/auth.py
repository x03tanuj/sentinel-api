"""Authentication utilities, JWT handling, and security dependencies for Target API."""

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.data import get_user_by_id

# OpenAPI security scheme declaration
bearer_scheme = HTTPBearer(auto_error=False, scheme_name="bearerAuth")


def is_secure() -> bool:
    """Read the SECURE environment variable at request time."""
    val = os.getenv("SECURE", "false").strip().lower()
    return val in ("true", "1", "yes")


def get_jwt_secret() -> str:
    """Retrieve secret key for signing JWT tokens."""
    return os.getenv("JWT_SECRET", "dev-secret-demo-only-32bytes-long!!")


def create_access_token(user_id: int, username: str, role: str, expires_delta: timedelta | None = None) -> str:
    """Create a signed HS256 JWT access token."""
    delta = expires_delta or timedelta(hours=1)
    expire = datetime.now(timezone.utc) + delta
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm="HS256")


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a signed JWT access token.

    Raises:
        HTTPException: If token is expired or invalid.
    """
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict[str, Any]:
    """Dependency that extracts and validates the authenticated user from the bearer token."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
        )

    payload = decode_access_token(credentials.credentials)
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
        )

    try:
        user_id = int(sub)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed user identifier in token",
        )

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
        )

    return user


def require_admin(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """Dependency enforcing that current user possesses the admin role."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required",
        )
    return current_user
