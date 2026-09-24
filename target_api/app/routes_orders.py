"""Orders router demonstrating BOLA read and write vulnerabilities."""

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.auth import get_current_user, is_secure
from app.data import (
    create_order,
    delete_order,
    get_order_by_id,
    get_orders_for_user,
    update_order,
)
from app.schemas import CreateOrderRequest, OrderResponse, UpdateOrderRequest

router = APIRouter(prefix="/orders", tags=["Orders"])


@router.get(
    "",
    response_model=list[OrderResponse],
    summary="List Current User's Orders",
    description="Retrieve all purchase orders placed by the authenticated user.",
    operation_id="list_orders",
)
def list_orders(current_user: dict[str, Any] = Depends(get_current_user)) -> list[OrderResponse]:
    """List caller's purchase orders (safe in both modes)."""
    orders = get_orders_for_user(current_user["id"])
    return [OrderResponse(**o) for o in orders]


@router.post(
    "",
    response_model=OrderResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create New Order",
    description="Place a new purchase order for the authenticated caller.",
    operation_id="create_order",
)
def place_order(
    req: CreateOrderRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> OrderResponse:
    """Create a new order for current user calculating total from catalog."""
    items_raw = [item.model_dump() for item in req.items]
    order = create_order(
        user_id=current_user["id"],
        items=items_raw,
        shipping_address=req.shipping_address,
    )
    return OrderResponse(**order)


@router.get(
    "/{id}",
    response_model=OrderResponse,
    summary="Get Order By ID",
    description="Retrieve details of a specific purchase order by ID.",
    operation_id="get_order_by_id",
)
def get_order(
    id: int,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> OrderResponse:
    """Fetch order details with conditional BOLA read flaw."""
    order = get_order_by_id(id)
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    # =========================================================================
    # VULN(BOLA): Allows any authenticated user to inspect orders belonging to other users.
    # FIX: Require caller to be the order owner or have admin role (403 otherwise).
    # =========================================================================
    if is_secure():
        # FIX: Validate caller is owner or administrator
        if order["user_id"] != current_user["id"] and current_user.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You are not authorized to view this order",
            )
    else:
        # VULN(BOLA): No ownership check performed
        pass

    return OrderResponse(**order)


@router.put(
    "/{id}",
    response_model=OrderResponse,
    summary="Update Order By ID",
    description="Update address or status of an existing order.",
    operation_id="update_order",
)
def edit_order(
    id: int,
    req: UpdateOrderRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> OrderResponse:
    """Update order details with conditional BOLA write flaw."""
    order = get_order_by_id(id)
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    # =========================================================================
    # VULN(BOLA write): Any authenticated user can modify shipping address/status of any order.
    # FIX: Restrict write access strictly to owner or administrator.
    # =========================================================================
    if is_secure():
        # FIX: Check authorization
        if order["user_id"] != current_user["id"] and current_user.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You cannot modify this order",
            )
    else:
        # VULN(BOLA write): Unchecked modification
        pass

    updated = update_order(
        order_id=id,
        shipping_address=req.shipping_address,
        status=req.status,
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    return OrderResponse(**updated)


@router.delete(
    "/{id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Order By ID",
    description="Cancel and delete an order record.",
    operation_id="delete_order",
)
def remove_order(
    id: int,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> Response:
    """Delete order with conditional BOLA write flaw."""
    order = get_order_by_id(id)
    if not order:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    # =========================================================================
    # VULN(BOLA write): Any authenticated user can delete other users' orders.
    # FIX: Restrict deletion to owner or administrator.
    # =========================================================================
    if is_secure():
        # FIX: Enforce ownership before deletion
        if order["user_id"] != current_user["id"] and current_user.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: You cannot delete this order",
            )
    else:
        # VULN(BOLA write): Unrestricted deletion
        pass

    delete_order(id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
