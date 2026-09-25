"""In-memory seed data and persistence for MedPulse Health API."""

import copy
import hashlib
from typing import Any


def _hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


SEED_PATIENTS: list[dict[str, Any]] = [
    {
        "id": 1,
        "username": "patientA",
        "password": "passA123",
        "password_hash": _hash_pw("passA123"),
        "full_name": "Eleanor Vance",
        "email": "eleanor.vance@medpulse.org",
        "ssn": "987-65-4321",
        "medical_record_no": "MRN-847291",
        "insurance_policy": "AETNA-GOLD-99120",
        "emergency_contact": "Thomas Vance (Spouse) - 555-0192",
        "role": "patient",
    },
    {
        "id": 2,
        "username": "patientB",
        "password": "passB123",
        "password_hash": _hash_pw("passB123"),
        "full_name": "Marcus Aurelius Thorne",
        "email": "marcus.thorne@medpulse.org",
        "ssn": "876-54-3210",
        "medical_record_no": "MRN-109284",
        "insurance_policy": "BCBS-PREMIER-44812",
        "emergency_contact": "Lucia Thorne (Sister) - 555-0843",
        "role": "patient",
    },
    {
        "id": 3,
        "username": "dr_smith",
        "password": "doctor123",
        "password_hash": _hash_pw("doctor123"),
        "full_name": "Dr. Sarah Smith, MD",
        "email": "dr.smith@medpulse.org",
        "ssn": "123-45-6789",
        "medical_record_no": "STAFF-DR-001",
        "insurance_policy": "STAFF-BENEFITS-001",
        "emergency_contact": "Hospital Security Desk - Ext 911",
        "role": "admin",
    },
]

SEED_RECORDS: list[dict[str, Any]] = [
    {
        "id": 201,
        "patient_id": 1,
        "doctor_name": "Dr. Sarah Smith, MD",
        "department": "Cardiology",
        "diagnosis": "Mild sinus bradycardia, stable. Routine follow-up scheduled.",
        "lab_results": "Cholesterol: 185 mg/dL, HDL: 55 mg/dL, LDL: 110 mg/dL, Triglycerides: 140 mg/dL.",
        "medications": ["Aspirin 81mg daily", "Multivitamin"],
        "notes": "Patient reports good exercise tolerance. No chest discomfort or dyspnea.",
        "date": "2026-08-14",
    },
    {
        "id": 202,
        "patient_id": 2,
        "doctor_name": "Dr. Gregory House, MD",
        "department": "Neurology & Oncology",
        "diagnosis": "Severe Chronic Cardiac Arrhythmia and Stage II Hypertension.",
        "lab_results": "Troponin-T: Elevated 0.04 ng/mL, Potassium: 3.2 mEq/L, Creatinine: 1.4 mg/dL.",
        "medications": ["Atorvastatin 40mg", "Metoprolol Succinate 50mg", "Lisinopril 20mg"],
        "notes": "CONFIDENTIAL: Patient undergoing evaluation for specialized surgical ablation therapy.",
        "date": "2026-09-02",
    },
]

SEED_PRESCRIPTIONS: list[dict[str, Any]] = [
    {
        "id": 501,
        "patient_id": 1,
        "medication": "Aspirin 81mg",
        "refills": 3,
        "prescribed_by": "Dr. Sarah Smith, MD",
        "controlled_substance": False,
        "dea_schedule": None,
    },
    {
        "id": 502,
        "patient_id": 2,
        "medication": "Oxycodone HCl 10mg",
        "refills": 0,
        "prescribed_by": "Dr. Gregory House, MD",
        "controlled_substance": True,
        "dea_schedule": "Schedule II",
    },
]

SEED_TRIALS: list[dict[str, Any]] = [
    {
        "id": "NCT-2026-CARDIO-99",
        "title": "Phase III Double-Blind Trial of Novel Beta-Blocker Compound MP-88",
        "sponsor": "MedPulse Therapeutics Global",
        "active_participants": 240,
        "target_endpoint": "30-day reduction in ventricular premature beats",
        "unblinded_preliminary_results": "Active drug arm shows 42% efficacy increase vs placebo.",
    }
]

# Mutable runtime storage
_patients: list[dict[str, Any]] = copy.deepcopy(SEED_PATIENTS)
_records: list[dict[str, Any]] = copy.deepcopy(SEED_RECORDS)
_prescriptions: list[dict[str, Any]] = copy.deepcopy(SEED_PRESCRIPTIONS)
_trials: list[dict[str, Any]] = copy.deepcopy(SEED_TRIALS)


def reset_data() -> None:
    global _patients, _records, _prescriptions, _trials
    _patients = copy.deepcopy(SEED_PATIENTS)
    _records = copy.deepcopy(SEED_RECORDS)
    _prescriptions = copy.deepcopy(SEED_PRESCRIPTIONS)
    _trials = copy.deepcopy(SEED_TRIALS)


def get_patients() -> list[dict[str, Any]]:
    return _patients


def get_patient_by_id(pid: int) -> dict[str, Any] | None:
    return next((p for p in _patients if p["id"] == pid), None)


def get_patient_by_username(username: str) -> dict[str, Any] | None:
    return next((p for p in _patients if p["username"] == username), None)


def get_records() -> list[dict[str, Any]]:
    return _records


def get_record_by_id(rid: int) -> dict[str, Any] | None:
    return next((r for r in _records if r["id"] == rid), None)


def get_prescriptions() -> list[dict[str, Any]]:
    return _prescriptions


def get_trials() -> list[dict[str, Any]]:
    return _trials
