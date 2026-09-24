"""Reports router demonstrating missing authentication flaw."""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from app.auth import bearer_scheme, decode_access_token, is_secure
from app.data import get_all_orders, get_all_users
from app.schemas import ReportSummaryResponse

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get(
    "/summary",
    response_model=ReportSummaryResponse,
    summary="Executive Summary Report",
    description="Calculates cumulative financial totals, active order volume, and registered user counts.",
    operation_id="get_reports_summary",
    openapi_extra={"security": [{"bearerAuth": []}]},
)
def get_summary_report(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> ReportSummaryResponse:
    """Produce executive aggregate report with conditional missing-auth flaw."""
    # =========================================================================
    # VULN(missing auth): The OpenAPI specification advertises bearerAuth requirement,
    # but the runtime implementation completely fails to check credentials.
    # FIX: Validate bearer token and reject unauthenticated requests with 401.
    # =========================================================================
    if is_secure():
        # FIX: Enforce authentication check
        if not credentials or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication credentials were not provided",
            )
        # Validate token signature and expiration
        decode_access_token(credentials.credentials)
    else:
        # VULN(missing auth): Ignores credentials; serves confidential metrics without auth
        pass

    orders = get_all_orders()
    users = get_all_users()
    total_revenue = sum(o["total"] for o in orders)

    return ReportSummaryResponse(
        total_orders=len(orders),
        total_revenue=round(total_revenue, 2),
        total_users=len(users),
    )
