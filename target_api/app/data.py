"""In-memory seed data, persistence state, and helper functions for Target API."""

import copy
import hashlib
from typing import Any

from app.ratelimit import clear_rate_limits


def _hash_pw(password: str) -> str:
    """Generate SHA256 hex digest for password (demo purpose)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


SEED_USERS: list[dict[str, Any]] = [
    {
        "id": 1,
        "username": "userA",
        "password": "passA123",
        "password_hash": _hash_pw("passA123"),
        "full_name": "Alice Anderson",
        "email": "userA@example.com",
        "ssn": "111-22-3333",
        "role": "user",
    },
    {
        "id": 2,
        "username": "userB",
        "password": "passB123",
        "password_hash": _hash_pw("passB123"),
        "full_name": "Bob Baker",
        "email": "userB@example.com",
        "ssn": "444-55-6666",
        "role": "user",
    },
    {
        "id": 3,
        "username": "admin",
        "password": "admin123",
        "password_hash": _hash_pw("admin123"),
        "full_name": "Super Administrator",
        "email": "admin@example.com",
        "ssn": "777-88-9999",
        "role": "admin",
    },
]

SEED_PRODUCTS: list[dict[str, Any]] = [
    {"id": 1, "name": "Mechanical Keyboard", "price": 120.0},
    {"id": 2, "name": "Wireless Mouse", "price": 60.0},
    {"id": 3, "name": "4K Ultra Monitor", "price": 400.0},
    {"id": 4, "name": "USB-C Multiport Hub", "price": 45.0},
    {"id": 5, "name": "Ergonomic Desk Mat", "price": 25.0},
]

SEED_ORDERS: list[dict[str, Any]] = [
    {
        "id": 101,
        "user_id": 1,
        "items": [{"product_id": 1, "qty": 1}, {"product_id": 2, "qty": 1}],
        "total": 180.0,
        "shipping_address": "123 Elm St, Springfield, IL 62701",
        "status": "delivered",
    },
    {
        "id": 102,
        "user_id": 1,
        "items": [{"product_id": 4, "qty": 2}],
        "total": 90.0,
        "shipping_address": "123 Elm St, Springfield, IL 62701",
        "status": "shipped",
    },
    {
        "id": 103,
        "user_id": 1,
        "items": [{"product_id": 5, "qty": 1}],
        "total": 25.0,
        "shipping_address": "123 Elm St, Springfield, IL 62701",
        "status": "pending",
    },
    {
        "id": 104,
        "user_id": 2,
        "items": [{"product_id": 3, "qty": 1}],
        "total": 400.0,
        "shipping_address": "456 Oak Ave, Metropolis, NY 10001",
        "status": "shipped",
    },
    {
        "id": 105,
        "user_id": 2,
        "items": [{"product_id": 2, "qty": 2}, {"product_id": 5, "qty": 2}],
        "total": 170.0,
        "shipping_address": "456 Oak Ave, Metropolis, NY 10001",
        "status": "delivered",
    },
    {
        "id": 106,
        "user_id": 3,
        "items": [{"product_id": 1, "qty": 2}, {"product_id": 3, "qty": 1}],
        "total": 640.0,
        "shipping_address": "789 Pine Rd, Gotham, NJ 07001",
        "status": "processing",
    },
]

# Active in-memory tables
users_db: dict[int, dict[str, Any]] = {}
products_db: dict[int, dict[str, Any]] = {}
orders_db: dict[int, dict[str, Any]] = {}


def reset_data() -> None:
    """Reset database to initial seed values and clear rate limit state."""
    users_db.clear()
    for u in copy.deepcopy(SEED_USERS):
        users_db[u["id"]] = u

    products_db.clear()
    for p in copy.deepcopy(SEED_PRODUCTS):
        products_db[p["id"]] = p

    orders_db.clear()
    for o in copy.deepcopy(SEED_ORDERS):
        orders_db[o["id"]] = o

    clear_rate_limits()


# Initial load at startup
reset_data()


def get_user_by_username(username: str) -> dict[str, Any] | None:
    """Retrieve user record by username."""
    for user in users_db.values():
        if user["username"] == username:
            return user
    return None


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    """Retrieve user record by numeric ID."""
    return users_db.get(user_id)


def get_all_users() -> list[dict[str, Any]]:
    """Retrieve all user records."""
    return list(users_db.values())


def get_product_by_id(product_id: int) -> dict[str, Any] | None:
    """Retrieve product record by numeric ID."""
    return products_db.get(product_id)


def get_all_products() -> list[dict[str, Any]]:
    """Retrieve all catalog products."""
    return list(products_db.values())


def get_order_by_id(order_id: int) -> dict[str, Any] | None:
    """Retrieve order record by numeric ID."""
    return orders_db.get(order_id)


def get_orders_for_user(user_id: int) -> list[dict[str, Any]]:
    """Retrieve all orders belonging to a specific user."""
    return [order for order in orders_db.values() if order["user_id"] == user_id]


def get_all_orders() -> list[dict[str, Any]]:
    """Retrieve all orders."""
    return list(orders_db.values())


def create_order(user_id: int, items: list[dict[str, Any]], shipping_address: str) -> dict[str, Any]:
    """Calculate order total from catalog and create a new order."""
    total = 0.0
    for item in items:
        prod = products_db.get(item["product_id"])
        if prod:
            total += prod["price"] * item["qty"]

    new_id = max(orders_db.keys(), default=100) + 1
    new_order = {
        "id": new_id,
        "user_id": user_id,
        "items": items,
        "total": round(total, 2),
        "shipping_address": shipping_address,
        "status": "pending",
    }
    orders_db[new_id] = new_order
    return new_order


def update_order(
    order_id: int,
    shipping_address: str | None = None,
    status: str | None = None,
) -> dict[str, Any] | None:
    """Update order fields if order exists."""
    order = orders_db.get(order_id)
    if not order:
        return None
    if shipping_address is not None:
        order["shipping_address"] = shipping_address
    if status is not None:
        order["status"] = status
    return order


def delete_order(order_id: int) -> bool:
    """Remove order from store."""
    if order_id in orders_db:
        del orders_db[order_id]
        return True
    return False
