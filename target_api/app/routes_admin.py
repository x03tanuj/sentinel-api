"""Admin management router demonstrating Broken Function Level Authorization (BFLA)."""

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import get_current_user, is_secure
from app.data import get_all_users
from app.schemas import UserFull

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get(
    "/users",
    response_model=list[UserFull],
    summary="List All Users (Admin)",
    description="Administrative endpoint retrieving complete internal user records.",
    operation_id="admin_list_users",
)
def list_all_users(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> list[UserFull]:
    """Retrieve full user catalog with conditional BFLA vulnerability."""
    # =========================================================================
    # VULN(BFLA): Any authenticated user can access administrative functions.
    # FIX: Strictly check if current_user['role'] == 'admin' (403 otherwise).
    # =========================================================================
    if is_secure():
        # FIX: Enforce role-based access control
        if current_user.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Administrative privileges required",
            )
    else:
        # VULN(BFLA): Bypasses administrative privilege verification
        pass

    users = get_all_users()
    return [UserFull(**u) for u in users]
