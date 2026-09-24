"""Authentication router implementing login and rate-limiting vulnerability toggle."""

import hmac
from fastapi import APIRouter, HTTPException, Request, Response, status

from app.auth import create_access_token, is_secure
from app.data import get_user_by_username
from app.ratelimit import check_rate_limit
from app.schemas import LoginRequest, LoginResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="User Login",
    description="Authenticate with username and password to obtain a bearer JWT token.",
    operation_id="login",
)
def login(req: LoginRequest, request: Request, response: Response) -> LoginResponse:
    """Authenticate user with optional rate-limiting enforcement."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    # =========================================================================
    # VULN(rate-limit): No rate-limiting in default mode permits brute-force attacks.
    # FIX: Enforce 10 attempts per 60s window, returning 429 + Retry-After on 11th.
    # =========================================================================
    if is_secure():
        # FIX: Check sliding-window rate limit
        allowed, retry_after = check_rate_limit(client_ip, max_attempts=10, window_seconds=60.0)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Retry after {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)},
            )
    else:
        # VULN(rate-limit): Permissive execution; no rate-limit counters checked or tracked.
        pass

    user = get_user_by_username(req.username)
    if not user or not hmac.compare_digest(user["password"], req.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(user["id"], user["username"], user["role"])
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user_id=user["id"],
        role=user["role"],
    )
