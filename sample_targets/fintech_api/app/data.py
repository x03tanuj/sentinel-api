"""In-memory seed data and persistence for ApexBank FinTech API."""

import copy
import hashlib
from typing import Any


def _hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


SEED_CLIENTS: list[dict[str, Any]] = [
    {
        "id": 1,
        "username": "clientA",
        "password": "passA123",
        "password_hash": _hash_pw("passA123"),
        "full_name": "Arthur Pendelton",
        "email": "arthur.pendelton@apexbank.io",
        "tax_id": "TAX-US-9918231",
        "role": "user",
    },
    {
        "id": 2,
        "username": "clientB",
        "password": "passB123",
        "password_hash": _hash_pw("passB123"),
        "full_name": "Beatrice Sterling",
        "email": "beatrice.sterling@apexbank.io",
        "tax_id": "TAX-US-7729104",
        "role": "user",
    },
    {
        "id": 3,
        "username": "auditor",
        "password": "audit123",
        "password_hash": _hash_pw("audit123"),
        "full_name": "Compliance & Fraud Officer",
        "email": "compliance@apexbank.io",
        "tax_id": "TAX-STAFF-001",
        "role": "admin",
    },
]

SEED_ACCOUNTS: list[dict[str, Any]] = [
    {
        "id": 301,
        "client_id": 1,
        "account_number": "ACT-8829-1092-A",
        "iban": "US89APEX000188291092A",
        "account_type": "Checking & Operating",
        "balance": 24500.50,
        "currency": "USD",
        "card_cvv_hash": "e3b0c44298fc1c149afbf4c8996fb924",
        "routing_number": "121000358",
    },
    {
        "id": 302,
        "client_id": 2,
        "account_number": "ACT-9941-4028-B",
        "iban": "US89APEX000199414028B",
        "account_type": "High-Yield Treasury Reserve",
        "balance": 184250.00,
        "currency": "USD",
        "card_cvv_hash": "8c6976e5b5410415bde908bd4dee15df",
        "routing_number": "121000358",
    },
]

SEED_TRANSFERS: list[dict[str, Any]] = [
    {
        "id": 701,
        "client_id": 1,
        "recipient_name": "Cloud Infra Services LLC",
        "amount": 1250.00,
        "currency": "USD",
        "status": "completed",
        "reference": "INV-2026-AUG-01",
        "timestamp": "2026-08-20T14:30:00Z",
    },
    {
        "id": 702,
        "client_id": 2,
        "recipient_name": "Offshore Capital Partners Ltd",
        "amount": 75000.00,
        "currency": "USD",
        "status": "pending_approval",
        "reference": "WIRE-OCT-77912",
        "timestamp": "2026-09-01T10:15:00Z",
    },
]

SEED_COMPLIANCE_LOGS: list[dict[str, Any]] = [
    {
        "id": "AML-LOG-4491",
        "flag_type": "Suspicious Activity Report (SAR)",
        "source_account": "ACT-9941-4028-B",
        "severity": "HIGH",
        "notes": "Large outbound wire $75,000 flagged for foreign transaction scrutiny.",
        "flagged_at": "2026-09-01T10:16:00Z",
    }
]

SEED_TREASURY: dict[str, Any] = {
    "total_deposits": 48250000.00,
    "liquidity_ratio": "18.4%",
    "fed_funds_rate_spread": "0.45%",
    "active_vault_reserve": 12500000.00,
    "last_rebalance": "2026-09-24T18:00:00Z",
}

_clients: list[dict[str, Any]] = copy.deepcopy(SEED_CLIENTS)
_accounts: list[dict[str, Any]] = copy.deepcopy(SEED_ACCOUNTS)
_transfers: list[dict[str, Any]] = copy.deepcopy(SEED_TRANSFERS)
_compliance_logs: list[dict[str, Any]] = copy.deepcopy(SEED_COMPLIANCE_LOGS)


def reset_data() -> None:
    global _clients, _accounts, _transfers, _compliance_logs
    _clients = copy.deepcopy(SEED_CLIENTS)
    _accounts = copy.deepcopy(SEED_ACCOUNTS)
    _transfers = copy.deepcopy(SEED_TRANSFERS)
    _compliance_logs = copy.deepcopy(SEED_COMPLIANCE_LOGS)


def get_clients() -> list[dict[str, Any]]:
    return _clients


def get_client_by_id(cid: int) -> dict[str, Any] | None:
    return next((c for c in _clients if c["id"] == cid), None)


def get_client_by_username(username: str) -> dict[str, Any] | None:
    return next((c for c in _clients if c["username"] == username), None)


def get_accounts() -> list[dict[str, Any]]:
    return _accounts


def get_account_by_id(aid: int) -> dict[str, Any] | None:
    return next((a for a in _accounts if a["id"] == aid), None)


def get_transfers() -> list[dict[str, Any]]:
    return _transfers


def get_transfer_by_id(tid: int) -> dict[str, Any] | None:
    return next((t for t in _transfers if t["id"] == tid), None)


def delete_transfer(tid: int) -> bool:
    global _transfers
    for idx, t in enumerate(_transfers):
        if t["id"] == tid:
            del _transfers[idx]
            return True
    return False


def get_compliance_logs() -> list[dict[str, Any]]:
    return _compliance_logs


def get_treasury() -> dict[str, Any]:
    return SEED_TREASURY
