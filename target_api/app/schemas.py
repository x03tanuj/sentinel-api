"""Pydantic schemas and contracts for Target API."""

from typing import Any
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """User credentials for authentication."""

    username: str = Field(..., description="User account username", examples=["userA"])
    password: str = Field(..., description="Account secret password", examples=["passA123"])


class LoginResponse(BaseModel):
    """JWT bearer token and authenticated user metadata."""

    access_token: str = Field(..., description="Signed JSON Web Token")
    token_type: str = Field(default="bearer", description="Token authorization type")
    user_id: int = Field(..., description="Authenticated user identifier")
    role: str = Field(..., description="User permission role")


class UserPublic(BaseModel):
    """Safe public user profile schema."""

    id: int = Field(..., description="User unique identifier")
    full_name: str = Field(..., description="User full legal name")
    email: str = Field(..., description="Contact email address")


class UserMe(BaseModel):
    """Safe authenticated profile for current caller."""

    id: int = Field(..., description="User unique identifier")
    username: str = Field(..., description="Account login username")
    full_name: str = Field(..., description="User full legal name")
    email: str = Field(..., description="Contact email address")
    role: str = Field(..., description="User authorization role")


class UserFull(BaseModel):
    """Full internal user record leaking sensitive identifiers."""

    id: int = Field(..., description="User unique identifier")
    username: str = Field(..., description="Account login username")
    password: str = Field(..., description="Plaintext demo password")
    password_hash: str = Field(..., description="Password hash digest")
    full_name: str = Field(..., description="User full legal name")
    email: str = Field(..., description="Contact email address")
    ssn: str = Field(..., description="Government Social Security Number")
    role: str = Field(..., description="User authorization role")


class OrderItem(BaseModel):
    """Single line item within a purchase order."""

    product_id: int = Field(..., description="Catalog product identifier")
    qty: int = Field(..., ge=1, description="Quantity of product ordered")


class CreateOrderRequest(BaseModel):
    """Payload to create a new customer purchase order."""

    items: list[OrderItem] = Field(..., min_length=1, description="Ordered product items")
    shipping_address: str = Field(..., description="Physical destination address")


class UpdateOrderRequest(BaseModel):
    """Payload to modify existing order metadata."""

    shipping_address: str | None = Field(default=None, description="Updated destination address")
    status: str | None = Field(default=None, description="Updated lifecycle status")


class OrderResponse(BaseModel):
    """Detailed purchase order response representation."""

    id: int = Field(..., description="Order unique identifier")
    user_id: int = Field(..., description="Owner customer identifier")
    items: list[OrderItem] = Field(..., description="Ordered items list")
    total: float = Field(..., description="Calculated monetary total")
    shipping_address: str = Field(..., description="Physical destination address")
    status: str = Field(..., description="Lifecycle order status, e.g. pending, shipped")


class ProductResponse(BaseModel):
    """Catalog product item response."""

    id: int = Field(..., description="Product unique identifier")
    name: str = Field(..., description="Display title of product")
    price: float = Field(..., description="Unit price of product")


class ReportSummaryResponse(BaseModel):
    """High-level executive financial and usage metrics."""

    total_orders: int = Field(..., description="Total count of orders created")
    total_revenue: float = Field(..., description="Sum total of revenue generated")
    total_users: int = Field(..., description="Count of registered users")


class HealthResponse(BaseModel):
    """Service status health check response."""

    status: str = Field(default="ok", description="Operational status flag")


class ResetResponse(BaseModel):
    """Result of state reset invocation."""

    status: str = Field(default="reset", description="Reset status confirmation")
