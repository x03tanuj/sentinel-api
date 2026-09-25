"""Pydantic schemas for MedPulse Health API."""

from typing import Any
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., description="Patient or doctor username", examples=["patientA"])
    password: str = Field(..., description="Account secret password", examples=["passA123"])


class LoginResponse(BaseModel):
    access_token: str = Field(..., description="Signed JSON Web Token")
    token_type: str = Field(default="bearer", description="Token authorization type")
    user_id: int = Field(..., description="Authenticated patient/doctor ID")
    role: str = Field(..., description="Authorization role: patient or admin")


class PatientProfile(BaseModel):
    id: int = Field(..., description="Patient record ID")
    username: str = Field(..., description="Portal login handle")
    full_name: str = Field(..., description="Full legal name")
    email: str = Field(..., description="Registered contact email")
    ssn: str = Field(..., description="Social Security Number (Sensitive PII)")
    medical_record_no: str = Field(..., description="Hospital Medical Record Number")
    insurance_policy: str = Field(..., description="Health insurance policy identifier")
    emergency_contact: str = Field(..., description="Emergency contact phone and name")
    role: str = Field(..., description="Access tier")


class MedicalRecord(BaseModel):
    id: int = Field(..., description="Clinical chart record ID")
    patient_id: int = Field(..., description="Associated patient ID")
    doctor_name: str = Field(..., description="Attending physician")
    department: str = Field(..., description="Medical department")
    diagnosis: str = Field(..., description="Clinical diagnostic evaluation")
    lab_results: str = Field(..., description="Laboratory test results")
    medications: list[str] = Field(..., description="Active medication schedule")
    notes: str = Field(..., description="Physician clinical notes")
    date: str = Field(..., description="Consultation date")


class UpdateRecordRequest(BaseModel):
    notes: str | None = Field(default=None, description="Updated clinical notes")
    diagnosis: str | None = Field(default=None, description="Updated diagnosis")


class PrescriptionRecord(BaseModel):
    id: int = Field(..., description="Prescription ID")
    patient_id: int = Field(..., description="Patient ID")
    medication: str = Field(..., description="Prescribed drug name & dosage")
    refills: int = Field(..., description="Authorized refills count")
    prescribed_by: str = Field(..., description="Prescribing physician")
    controlled_substance: bool = Field(..., description="Flag if controlled substance")
    dea_schedule: str | None = Field(default=None, description="DEA regulatory schedule")


class HealthResponse(BaseModel):
    status: str = Field(default="ok", description="Service status")
    service: str = Field(default="MedPulse Health Portal", description="Service name")


class ResetResponse(BaseModel):
    status: str = Field(default="reset", description="Reset status")
