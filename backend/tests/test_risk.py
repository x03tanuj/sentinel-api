"""Unit tests for the explainable Risk Engine and severity computation."""

import pytest

from app.engine.differential import DiffResult
from app.engine.risk import (
    ImpactFactor,
    RiskInputs,
    compute_severity,
    infer_impact_factor,
    sequential_ids_bonus,
)
from app.models import Severity

ALL_CHECKS = ["bola", "bfla", "data_exposure", "rate_limit", "unauth_access", "input_handling"]
GET_WRITE_METHODS = ["GET", "PUT", "PATCH", "DELETE", "POST"]


@pytest.mark.parametrize("check", ALL_CHECKS)
@pytest.mark.parametrize("method", GET_WRITE_METHODS)
def test_infer_impact_factor_exhaustive(check: str, method: str) -> None:
    """Verify infer_impact_factor maps exhaustively for all checks and methods."""
    factor = infer_impact_factor(check_name=check, method=method)
    assert isinstance(factor, ImpactFactor)
    assert factor in (
        ImpactFactor.WRITE,
        ImpactFactor.PRIVILEGE_ESCALATION,
        ImpactFactor.UNAUTHENTICATED_ACCESS,
        ImpactFactor.READ,
    )


def test_infer_impact_factor_specific_mappings() -> None:
    """Verify specific expected ImpactFactor assignments."""
    assert infer_impact_factor("bola", "PUT") == ImpactFactor.WRITE
    assert infer_impact_factor("bola", "GET") == ImpactFactor.READ
    assert infer_impact_factor("bfla", "GET") == ImpactFactor.PRIVILEGE_ESCALATION
    assert infer_impact_factor("unauth_access", "GET") == ImpactFactor.UNAUTHENTICATED_ACCESS
    assert infer_impact_factor("rate_limit", "POST") == ImpactFactor.READ
    assert infer_impact_factor("data_exposure", "GET") == ImpactFactor.READ


def test_compute_severity_write_bola_secret_tier_critical() -> None:
    """Write-BOLA with SECRET-tier data and no auth must be CRITICAL."""
    diff = DiffResult(
        status_changed=False,
        baseline_status=200,
        attack_status=200,
        body_similarity=0.95,
        schema_similarity=1.0,
        same_object_id=True,
        owner_id_differs=True,
        sensitive_fields_exposed={"SECRET": ["password_hash", "ssn"]},
        size_ratio=1.0,
        changed_fields=[],
        attack_body_empty=False,
        attack_body_is_error=False,
    )
    inputs = RiskInputs(
        check_name="bola",
        method="PUT",
        requires_auth=False,
        diff=diff,
    )
    sev, score = compute_severity(inputs)
    assert sev == Severity.CRITICAL
    assert score >= 80


def test_compute_severity_low_tier_readonly_weak_evidence() -> None:
    """A LOW-tier read-only leak with weak evidence must be LOW or INFO."""
    diff_low = DiffResult(
        status_changed=False,
        baseline_status=200,
        attack_status=200,
        body_similarity=0.20,
        schema_similarity=0.40,
        same_object_id=None,
        owner_id_differs=None,
        sensitive_fields_exposed={"LOW": ["role"]},
        size_ratio=1.0,
        changed_fields=[],
        attack_body_empty=False,
        attack_body_is_error=False,
    )
    inputs = RiskInputs(
        check_name="data_exposure",
        method="GET",
        requires_auth=True,
        diff=diff_low,
    )
    sev, score = compute_severity(inputs)
    assert sev in (Severity.LOW, Severity.INFO)
    assert score < 35


def test_compute_severity_score_clamping() -> None:
    """Verify scores clamp at 100 maximum and never go below 0."""
    diff_max = DiffResult(
        status_changed=True,
        baseline_status=403,
        attack_status=200,
        body_similarity=1.0,
        schema_similarity=1.0,
        same_object_id=True,
        owner_id_differs=True,
        sensitive_fields_exposed={"SECRET": ["token", "ssn", "password_hash"]},
        size_ratio=1.0,
        changed_fields=[],
        attack_body_empty=False,
        attack_body_is_error=False,
    )
    inputs_max = RiskInputs(
        check_name="bola",
        method="PUT",
        requires_auth=False,
        object_id_sequential=True,
        diff=diff_max,
    )
    sev_max, score_max = compute_severity(inputs_max)
    assert sev_max == Severity.CRITICAL
    assert score_max <= 100

    inputs_min = RiskInputs(
        check_name="input_handling",
        method="GET",
        requires_auth=True,
        has_data=False,
        diff=None,
    )
    sev_min, score_min = compute_severity(inputs_min)
    assert score_min >= 0
    assert sev_min in (Severity.INFO, Severity.LOW)


def test_sequential_ids_bonus() -> None:
    """sequential_ids_bonus applies (+5) only with provably sequential IDs."""
    # Provably sequential: diffs between sorted numbers are <= 2
    assert sequential_ids_bonus([101, 102, 103]) == 5
    assert sequential_ids_bonus(["101", "102", "103"]) == 5
    assert sequential_ids_bonus([10, 12, 14]) == 5

    # Non-sequential / sparse numbers
    assert sequential_ids_bonus([7, 481, 92]) == 0
    assert sequential_ids_bonus(["foo", "bar"]) == 0
    assert sequential_ids_bonus([1]) == 0
    assert sequential_ids_bonus(False) == 0
    assert sequential_ids_bonus(True) == 5
