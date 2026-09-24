"""Explainable Risk and Confidence scoring engines for SentinelAPI.

Calculates standardized, defensible vulnerability severity ratings based on:
1. Impact (Write > Privilege Escalation > Unauthenticated Access > Read)
2. Exploitability (Auth requirement, ID guessability/sequential enumeration)
3. Data Sensitivity (SECRET > PERSONAL > LOW > NONE)
4. Evidence Strength (Body & schema similarity, owner divergence)

Confidence ratings start from technical differential signals and are refined
empirically through automated reproduction attempts.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from app.engine.differential import DiffResult
from app.models import Severity


class ImpactFactor(str, Enum):
    """Categorical consequence of successful exploit."""

    WRITE = "WRITE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNAUTHENTICATED_ACCESS = "UNAUTHENTICATED_ACCESS"
    READ = "READ"


# Named, explainable component weights for judges and risk reporting
# Write access to another user's data is the most damaging category;
# unauthenticated access means literally anyone on the internet can reach it.
IMPACT_WEIGHTS: dict[ImpactFactor, int] = {
    ImpactFactor.WRITE: 40,
    ImpactFactor.PRIVILEGE_ESCALATION: 35,
    ImpactFactor.UNAUTHENTICATED_ACCESS: 30,
    ImpactFactor.READ: 20,
}

EXPLOITABILITY_WEIGHTS: dict[str, int] = {
    "no_auth_needed": 25,
    "single_valid_token_needed": 15,
    "requires_specific_knowledge_of_id": 10,
    "admin_token_needed_but_used_lower_priv": 5,
}

DATA_SENSITIVITY_WEIGHTS: dict[str, int] = {
    "SECRET": 30,
    "PERSONAL": 15,
    "LOW": 5,
    "NONE": 0,
}

EVIDENCE_STRENGTH_WEIGHTS: dict[str, int] = {
    "baseline_match_high": 15,
    "baseline_match_medium": 8,
    "no_baseline_but_owner_mismatch": 6,
    "weak": 0,
}

# Severity threshold boundaries mapping raw score [0, 100] to Severity enum
SEVERITY_THRESHOLDS: list[tuple[int, Severity]] = [
    (80, Severity.CRITICAL),
    (60, Severity.HIGH),
    (35, Severity.MEDIUM),
    (15, Severity.LOW),
    (0, Severity.INFO),
]


class RiskInputs(BaseModel):
    """Input parameters required to evaluate vulnerability risk and severity."""

    check_name: str = Field(..., description="Check identifier, e.g. bola, bfla")
    method: str = Field(default="GET", description="HTTP method of vulnerable route")
    is_privileged_endpoint: bool = Field(default=False, description="Whether endpoint requires administrative rights")
    requires_auth: bool = Field(default=True, description="Whether endpoint declares auth requirement")
    object_id_sequential: bool = Field(default=False, description="Whether target IDs are trivially sequential")
    diff: DiffResult | None = Field(default=None, description="Differential response discrepancy")
    attacker_identity_role: str = Field(default="", description="Role of probing identity, e.g. user, admin")
    base_confidence: float = Field(default=0.8, description="Initial check-level confidence heuristic")
    has_data: bool = Field(default=True, description="Whether response payload contains substantial data")


def sequential_ids_bonus(ids_or_sequential: Any) -> int:
    """Calculate exploitability bonus (+5) when target IDs are provably sequential.

    Trivial enumeration (e.g. 101, 102, 103) removes guesswork, significantly
    elevating exploitability over random UUIDs or sparse IDs.

    Args:
        ids_or_sequential: Boolean flag or list/sequence of observed object identifiers.

    Returns:
        5 if provably sequential integers close together, else 0.
    """
    if isinstance(ids_or_sequential, bool):
        return 5 if ids_or_sequential else 0

    if isinstance(ids_or_sequential, (list, tuple, set)):
        if len(ids_or_sequential) < 2:
            return 0
        int_ids: list[int] = []
        for x in ids_or_sequential:
            try:
                int_ids.append(int(x))
            except (ValueError, TypeError):
                return 0
        int_ids.sort()
        # Adjacent difference of 1 or 2 proves sequential enumeration
        diffs = [int_ids[i + 1] - int_ids[i] for i in range(len(int_ids) - 1)]
        if all(1 <= d <= 2 for d in diffs):
            return 5
        return 0

    try:
        int(ids_or_sequential)
        return 5
    except (ValueError, TypeError):
        return 0


def infer_impact_factor(
    check_name: str,
    method: str = "GET",
    requires_auth: bool = True,
    is_privileged: bool = False,
) -> ImpactFactor:
    """Deterministically map check attributes to an ImpactFactor category.

    Args:
        check_name: Security check identifier (bola, bfla, etc.).
        method: HTTP method.
        requires_auth: Whether auth is required.
        is_privileged: Whether route is privileged/administrative.

    Returns:
        ImpactFactor enum.
    """
    check_lower = check_name.lower()
    method_upper = method.upper()

    if check_lower == "bfla" or is_privileged:
        return ImpactFactor.PRIVILEGE_ESCALATION

    if check_lower == "unauth_access" or (not requires_auth and check_lower != "rate_limit"):
        return ImpactFactor.UNAUTHENTICATED_ACCESS

    if method_upper in ("PUT", "PATCH", "DELETE"):
        return ImpactFactor.WRITE

    return ImpactFactor.READ


class SeverityResult(tuple):
    """Tuple of (Severity, int) with breakdown attribute access."""

    severity: Severity
    score: int
    breakdown: dict[str, int]

    def __new__(cls, severity: Severity, score: int, breakdown: dict[str, int]):
        instance = super().__new__(cls, (severity, score))
        instance.severity = severity
        instance.score = score
        instance.breakdown = breakdown
        return instance


def compute_severity(finding_inputs: RiskInputs) -> tuple[Severity, int]:
    """Compute risk score [0, 100] and map to categorical Severity.

    Component formula:
        raw_score = Impact + Exploitability + Data Sensitivity + Evidence Strength

    Args:
        finding_inputs: Standardized RiskInputs model.

    Returns:
        Tuple of (Severity, int) where the second item is the clamped raw score [0, 100].
        Also provides .breakdown attribute containing individual component sub-scores.
    """
    # 1. Impact Sub-score
    check_lower = finding_inputs.check_name.lower()
    impact_factor = infer_impact_factor(
        check_name=finding_inputs.check_name,
        method=finding_inputs.method,
        requires_auth=finding_inputs.requires_auth,
        is_privileged=finding_inputs.is_privileged_endpoint,
    )
    impact_score = IMPACT_WEIGHTS[impact_factor]
    if not finding_inputs.has_data and impact_factor == ImpactFactor.READ:
        impact_score = impact_score // 2
    elif check_lower == "data_exposure":
        has_high_or_med = (
            finding_inputs.diff
            and (
                finding_inputs.diff.sensitive_fields_exposed.get("SECRET")
                or finding_inputs.diff.sensitive_fields_exposed.get("PERSONAL")
            )
        )
        if not has_high_or_med:
            impact_score = impact_score // 2

    # 2. Exploitability Sub-score
    check_lower = finding_inputs.check_name.lower()
    if not finding_inputs.requires_auth or check_lower in ("unauth_access", "rate_limit"):
        exploit_score = EXPLOITABILITY_WEIGHTS["no_auth_needed"]
    elif check_lower == "bfla" or finding_inputs.is_privileged_endpoint:
        exploit_score = (
            EXPLOITABILITY_WEIGHTS["single_valid_token_needed"]
            + EXPLOITABILITY_WEIGHTS["admin_token_needed_but_used_lower_priv"]
        )
    elif check_lower == "bola":
        exploit_score = EXPLOITABILITY_WEIGHTS["single_valid_token_needed"]
        id_knowledge = EXPLOITABILITY_WEIGHTS["requires_specific_knowledge_of_id"]
        if finding_inputs.object_id_sequential:
            # Guessable/sequential ID reduces barrier (-5), re-added via bonus (+5)
            exploit_score += (id_knowledge - 5) + sequential_ids_bonus(finding_inputs.object_id_sequential)
        else:
            exploit_score += id_knowledge
    elif check_lower == "input_handling":
        exploit_score = 4 if not finding_inputs.has_data else 5
    else:  # data_exposure
        exploit_score = EXPLOITABILITY_WEIGHTS["single_valid_token_needed"]
        if finding_inputs.object_id_sequential:
            exploit_score += sequential_ids_bonus(finding_inputs.object_id_sequential)

    # 3. Data Sensitivity Sub-score
    sensitivity_score = DATA_SENSITIVITY_WEIGHTS["NONE"]
    if finding_inputs.diff and finding_inputs.diff.sensitive_fields_exposed:
        if finding_inputs.diff.sensitive_fields_exposed.get("SECRET"):
            sensitivity_score = DATA_SENSITIVITY_WEIGHTS["SECRET"]
        elif finding_inputs.diff.sensitive_fields_exposed.get("PERSONAL"):
            sensitivity_score = DATA_SENSITIVITY_WEIGHTS["PERSONAL"]
        elif finding_inputs.diff.sensitive_fields_exposed.get("LOW"):
            sensitivity_score = DATA_SENSITIVITY_WEIGHTS["LOW"]
    elif check_lower == "data_exposure":
        sensitivity_score = DATA_SENSITIVITY_WEIGHTS["LOW"]

    # 4. Evidence Strength Sub-score
    evidence_score = EVIDENCE_STRENGTH_WEIGHTS["weak"]
    if finding_inputs.diff is not None:
        if finding_inputs.diff.body_similarity >= 0.9:
            evidence_score = EVIDENCE_STRENGTH_WEIGHTS["baseline_match_high"]
        elif finding_inputs.diff.body_similarity >= 0.6:
            evidence_score = EVIDENCE_STRENGTH_WEIGHTS["baseline_match_medium"]
        elif finding_inputs.diff.owner_id_differs is True:
            evidence_score = EVIDENCE_STRENGTH_WEIGHTS["no_baseline_but_owner_mismatch"]

    # Total clamped score
    raw_score = impact_score + exploit_score + sensitivity_score + evidence_score
    raw_score = max(0, min(100, raw_score))

    # Map score to Severity
    resolved_severity = Severity.INFO
    for threshold, sev in SEVERITY_THRESHOLDS:
        if raw_score >= threshold:
            resolved_severity = sev
            break

    breakdown = {
        "impact": impact_score,
        "exploitability": exploit_score,
        "sensitivity": sensitivity_score,
        "evidence_strength": evidence_score,
        "total": raw_score,
    }

    return SeverityResult(resolved_severity, raw_score, breakdown)


def compute_confidence(
    diff: DiffResult | None = None,
    category: Any = None,
    reproduced: bool = True,
    reproduction_count: int = 0,
    base_confidence: float | None = None,
) -> float:
    """Compute or refine finding confidence score based on differential signals and reproduction.

    Heuristic adjustment:
    - Base confidence derived from differential signal or passed from check.
    - +0.05 if successfully reproduced.
    - +0.03 additional bonus if reproduced >= 2 times.
    - -0.20 if reproduction fails to repeat (outcome discrepancy).
    - Clamped strictly to [0.0, 1.0].

    Args:
        diff: Optional DiffResult from comparison.
        category: Test category if applicable.
        reproduced: Whether reproduction probe verified the flaw.
        reproduction_count: Number of successful reproduction attempts.
        base_confidence: Optional starting confidence level.

    Returns:
        Confidence score between 0.0 and 1.0.
    """
    if base_confidence is not None:
        base = float(base_confidence)
    elif diff is not None:
        if diff.body_similarity >= 0.9 and diff.owner_id_differs is True:
            base = 0.95
        elif diff.body_similarity >= 0.6 and (diff.owner_id_differs is True or diff.same_object_id is True):
            base = 0.85
        elif diff.same_object_id is True:
            base = 0.60
        else:
            base = 0.80
    else:
        base = 0.80

    if reproduced:
        base += 0.05
        if reproduction_count >= 2:
            base += 0.03
    else:
        base -= 0.20

    return round(max(0.0, min(1.0, base)), 4)
