"""Pydantic schemas for ApexBank FinTech API."""

from typing import Any
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., description="Banking username", examples=["clientA"])
    password: str = Field(..., description="Banking secret password", examples=["passA123"])


class LoginResponse(BaseModel):
    access_token: str = Field(..., description="Signed JSON Web Token")
    token_type: str = Field(default="bearer", description="Token type")
    user_id: int = Field(..., description="Client user ID")
    role: str = Field(..., description="Account role: user or admin")


class ClientProfile(BaseModel):
    id: int = Field(..., description="Client ID")
    username: str = Field(..., description="Username handle")
    full_name: str = Field(..., description="Account holder full legal name")
    email: str = Field(..., description="Notification email")
    tax_id: str = Field(..., description="Taxpayer Identification Number (TIN / SSN)")
    role: str = Field(..., description="Role tier")


class BankAccount(BaseModel):
    id: int = Field(..., description="Internal account ID")
    client_id: int = Field(..., description="Owner client ID")
    account_number: str = Field(..., description="Bank account number")
    iban: str = Field(..., description="International Bank Account Number (IBAN)")
    account_type: str = Field(..., description="Checking, Savings, or Treasury")
    balance: float = Field(..., description="Current balance")
    currency: str = Field(default="USD", description="Currency code")
    card_cvv_hash: str = Field(..., description="Cryptographic CVV verification hash")
    routing_number: str = Field(..., description="Fedwire routing number")


class WireTransfer(BaseModel):
    id: int = Field(..., description="Transfer transaction ID")
    client_id: int = Field(..., description="Originating client ID")
    recipient_name: str = Field(..., description="Beneficiary name")
    amount: float = Field(..., description="Transfer amount")
    currency: str = Field(default="USD", description="Currency code")
    status: str = Field(..., description="Transfer lifecycle status")
    reference: str = Field(..., description="Payment reference")
    timestamp: str = Field(..., description="Transaction execution timestamp")


class ComplianceLog(BaseModel):
    id: str = Field(..., description="AML log ID")
    flag_type: str = Field(..., description="Compliance flag category")
    source_account: str = Field(..., description="Account number under scrutiny")
    severity: str = Field(..., description="Risk severity")
    notes: str = Field(..., description="Investigator notes")
    flagged_at: str = Field(..., description="Timestamp")


class HealthResponse(BaseModel):
    status: str = Field(default="ok", description="Status code")
    service: str = Field(default="ApexBank Digital API", description="Service name")


class ResetResponse(BaseModel):
    status: str = Field(default="reset", description="Reset status")
