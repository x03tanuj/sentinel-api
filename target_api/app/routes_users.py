"""User management routes demonstrating BOLA and Excessive Data Exposure flaws."""

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse

from app.auth import get_current_user, is_secure
from app.data import get_user_by_id
from app.schemas import UserMe, UserPublic

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "/me",
    response_model=UserMe,
    summary="Get Current User Profile",
    description="Retrieve the authenticated caller's own safe user profile details.",
    operation_id="get_current_user",
)
def get_me(current_user: dict[str, Any] = Depends(get_current_user)) -> UserMe:
    """Return authenticated caller's profile (safe in both modes)."""
    return UserMe(
        id=current_user["id"],
        username=current_user["username"],
        full_name=current_user["full_name"],
        email=current_user["email"],
        role=current_user["role"],
    )


@router.get(
    "/{id}",
    response_model=UserPublic,
    summary="Get User By ID",
    description="Retrieve public profile of a user by numeric user identifier.",
    operation_id="get_user_by_id",
)
def get_user(
    id: int,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> Any:
    """Fetch user profile with conditional BOLA and Excessive Data Exposure flaws."""
    target_user = get_user_by_id(id)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # =========================================================================
    # VULN(excessive data exposure + BOLA): Any user can inspect any other user,
    # and the returned JSON contains password_hash, ssn, and internal role.
    # FIX: Strictly enforce owner check (403 if id != current_user.id) and return
    # only the safe UserPublic schema.
    # =========================================================================
    if is_secure():
        # FIX: Check object ownership
        if id != current_user["id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Cannot access other users' profiles",
            )
        # FIX: Return strictly sanitized public schema
        return UserPublic(
            id=target_user["id"],
            full_name=target_user["full_name"],
            email=target_user["email"],
        )
    else:
        # VULN(BOLA + excessive data exposure): Leaks full record including ssn and password_hash
        return JSONResponse(content=target_user)
