"""Public product catalog router with no authentication requirement."""

from fastapi import APIRouter, HTTPException, status

from app.data import get_all_products, get_product_by_id
from app.schemas import ProductResponse

router = APIRouter(prefix="/products", tags=["Products"])


@router.get(
    "",
    response_model=list[ProductResponse],
    summary="List Catalog Products",
    description="Retrieve list of all catalog products available for purchase.",
    operation_id="list_products",
)
def list_products() -> list[ProductResponse]:
    """Return all products (public in both secure and vulnerable modes)."""
    products = get_all_products()
    return [ProductResponse(**p) for p in products]


@router.get(
    "/{id}",
    response_model=ProductResponse,
    summary="Get Product By ID",
    description="Retrieve single product details by identifier.",
    operation_id="get_product",
)
def get_product(id: int) -> ProductResponse:
    """Return specific product (public in both secure and vulnerable modes)."""
    product = get_product_by_id(id)
    if not product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Product not found",
        )
    return ProductResponse(**product)
