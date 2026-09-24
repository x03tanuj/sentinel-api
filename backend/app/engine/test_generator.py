"""Budgeted test case generator for API security scanning in SentinelAPI.

Operationalizes the attack surface and authorization matrix into prioritized,
deduplicated TestCases across six distinct vulnerability probe categories.
"""

from enum import Enum
from typing import Any, NamedTuple
from uuid import uuid4

from pydantic import BaseModel, Field

from app.engine.auth_matrix import MatrixCell, Outcome
from app.engine.discovery import OwnedObject
from app.models import Endpoint, Identity
from app.parser.risk_prioritizer import score_endpoint


class TestCategory(str, Enum):
    """Categorical classification of generated security test cases."""

    __test__ = False

    CROSS_USER = "CROSS_USER"
    ADJACENT_ID = "ADJACENT_ID"
    BOUNDARY = "BOUNDARY"
    INVALID_TYPE = "INVALID_TYPE"
    ANONYMOUS = "ANONYMOUS"
    PRIVILEGED_ENDPOINT = "PRIVILEGED_ENDPOINT"


class TestCase(BaseModel):
    """Specification of a concrete API probe test case to execute."""

    __test__ = False

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique test case identifier")
    endpoint: Endpoint = Field(..., description="Target API endpoint specification")
    identity_name: str = Field(..., description="Identity persona executing the probe")
    object_id: str | None = Field(default=None, description="Target object identifier probed")
    category: TestCategory = Field(..., description="Vulnerability category of probe")
    expected_outcome: Outcome = Field(..., description="Ground-truth expected authorization outcome")
    owner_identity: str | None = Field(default=None, description="Legitimate owner identity of object if known")
    notes: str = Field(default="", description="Descriptive context or hypothesis for test case")


class GenerationResult(NamedTuple):
    """Container holding generated test cases and category-level generation statistics."""

    cases: list[TestCase]
    stats: dict[str, Any]


def generate_cross_user_cases(
    endpoints: list[Endpoint],
    matrix_cells: list[MatrixCell],
) -> list[TestCase]:
    """Generate cross-user (BOLA/IDOR) test cases from DENY cells in the authorization matrix.

    For every object-level endpoint and every MatrixCell whose expected outcome is DENY
    for that endpoint's resource, generates a TestCase attempting cross-user access.

    Args:
        endpoints: Attack surface endpoints.
        matrix_cells: Ground-truth authorization matrix cells.

    Returns:
        List of CROSS_USER TestCase specifications.
    """
    cases: list[TestCase] = []

    # Map object-level endpoints by resource
    res_endpoints: dict[str, list[Endpoint]] = {}
    for ep in endpoints:
        if ep.is_object_level and ep.resource:
            res_endpoints.setdefault(ep.resource, []).append(ep)

    for cell in matrix_cells:
        if cell.expected == Outcome.DENY and cell.resource in res_endpoints:
            for ep in res_endpoints[cell.resource]:
                cases.append(
                    TestCase(
                        endpoint=ep,
                        identity_name=cell.identity,
                        object_id=cell.object_id,
                        category=TestCategory.CROSS_USER,
                        expected_outcome=Outcome.DENY,
                        owner_identity=cell.owner_identity,
                        notes=(
                            f"Cross-user BOLA probe: {cell.identity} attempting access "
                            f"to {cell.resource} '{cell.object_id}' owned by {cell.owner_identity}"
                        ),
                    )
                )

    return cases


def generate_adjacent_id_cases(
    endpoints: list[Endpoint],
    owned: dict[str, dict[str, list[OwnedObject]]],
) -> list[TestCase]:
    """Generate ID enumeration test cases (id - 1 and id + 1) for numeric object identifiers.

    Expected outcome is DENY unless the adjacent identifier is independently owned
    by that same identity.

    Args:
        endpoints: Attack surface endpoints.
        owned: Discovered object ownership mapping.

    Returns:
        List of ADJACENT_ID TestCase specifications.
    """
    cases: list[TestCase] = []
    res_endpoints: dict[str, list[Endpoint]] = {}
    for ep in endpoints:
        if ep.is_object_level and ep.resource:
            res_endpoints.setdefault(ep.resource, []).append(ep)

    for ident_name, res_dict in owned.items():
        if ident_name == "anonymous":
            continue

        for res_name, obj_list in res_dict.items():
            if res_name not in res_endpoints:
                continue

            known_ids_for_ident = {str(o.object_id) for o in obj_list}

            for obj in obj_list:
                try:
                    num_id = int(str(obj.object_id))
                except ValueError:
                    continue  # non-numeric ID, skip adjacent enumeration

                for adj_id in (num_id - 1, num_id + 1):
                    adj_str = str(adj_id)
                    expected = Outcome.ALLOW if adj_str in known_ids_for_ident else Outcome.DENY

                    for ep in res_endpoints[res_name]:
                        cases.append(
                            TestCase(
                                endpoint=ep,
                                identity_name=ident_name,
                                object_id=adj_str,
                                category=TestCategory.ADJACENT_ID,
                                expected_outcome=expected,
                                owner_identity=ident_name if expected == Outcome.ALLOW else None,
                                notes=f"Adjacent ID enumeration ({adj_str}) derived from owned object {num_id}",
                            )
                        )

    return cases


def generate_boundary_cases(
    endpoints: list[Endpoint],
    identity_name: str = "userA",
    extra_boundary_ids: list[str] | None = None,
) -> list[TestCase]:
    """Generate boundary condition test cases for object-level endpoints.

    Probes extreme values ('0', '-1', '999999999', non-existent UUIDs, and optional extra_boundary_ids) expecting DENY.

    Args:
        endpoints: Attack surface endpoints.
        identity_name: Default test persona to execute the probe.
        extra_boundary_ids: Optional extra boundary IDs suggested by AI.

    Returns:
        List of BOUNDARY TestCase specifications.
    """
    cases: list[TestCase] = []
    boundary_values = ["0", "-1", "999999999", "00000000-0000-0000-0000-000000000000"]
    if extra_boundary_ids:
        for bid in extra_boundary_ids:
            if bid not in boundary_values:
                boundary_values.append(bid)

    for ep in endpoints:
        if not ep.is_object_level:
            continue

        for val in boundary_values:
            cases.append(
                TestCase(
                    endpoint=ep,
                    identity_name=identity_name,
                    object_id=val,
                    category=TestCategory.BOUNDARY,
                    expected_outcome=Outcome.DENY,
                    owner_identity=None,
                    notes=f"Boundary condition probe with non-standard object ID '{val}'",
                )
            )

    return cases


def generate_invalid_type_cases(
    endpoints: list[Endpoint],
    identity_name: str = "userA",
) -> list[TestCase]:
    """Generate type-confusion and robustness test cases for object-level endpoints.

    Note:
        This is a lightweight input robustness and parameter-handling check, NOT a full
        SQL injection or SSTI exploit scanner, and should never be advertised as such.

    Args:
        endpoints: Attack surface endpoints.
        identity_name: Default test persona to execute the probe.

    Returns:
        List of INVALID_TYPE TestCase specifications.
    """
    cases: list[TestCase] = []
    invalid_values = ["abc", "1;drop", "' OR '1'='1", "{{7*7}}"]

    for ep in endpoints:
        if not ep.is_object_level:
            continue

        for val in invalid_values:
            cases.append(
                TestCase(
                    endpoint=ep,
                    identity_name=identity_name,
                    object_id=val,
                    category=TestCategory.INVALID_TYPE,
                    expected_outcome=Outcome.DENY,
                    owner_identity=None,
                    notes=f"Type-confusion and malformed parameter probe '{val}'",
                )
            )

    return cases


def generate_anonymous_cases(
    endpoints: list[Endpoint],
    owned: dict[str, dict[str, list[OwnedObject]]],
) -> list[TestCase]:
    """Generate unauthenticated access test cases for protected endpoints.

    For every requires_auth endpoint, probes without authentication expecting DENY.

    Args:
        endpoints: Attack surface endpoints.
        owned: Discovered object ownership mapping to derive representative object IDs.

    Returns:
        List of ANONYMOUS TestCase specifications.
    """
    cases: list[TestCase] = []

    # Map representative ID per resource
    sample_ids: dict[str, str] = {}
    for res_dict in owned.values():
        for res, objs in res_dict.items():
            if objs and res not in sample_ids:
                sample_ids[res] = str(objs[0].object_id)

    for ep in endpoints:
        if not ep.requires_auth:
            continue

        target_obj_id: str | None = None
        if ep.is_object_level:
            target_obj_id = sample_ids.get(ep.resource or "", "1")

        cases.append(
            TestCase(
                endpoint=ep,
                identity_name="anonymous",
                object_id=target_obj_id,
                category=TestCategory.ANONYMOUS,
                expected_outcome=Outcome.DENY,
                owner_identity=None,
                notes=f"Unauthenticated access probe against protected route {ep.method} {ep.path}",
            )
        )

    return cases


def generate_privileged_cases(
    endpoints: list[Endpoint],
    identities: list[Identity],
) -> list[TestCase]:
    """Generate broken function level authorization (BFLA) test cases for privileged routes.

    Probes administrative endpoints with regular non-admin identities expecting DENY.
    Admin personas are excluded as they represent legitimate baseline access.

    Args:
        endpoints: Attack surface endpoints.
        identities: Persona identities.

    Returns:
        List of PRIVILEGED_ENDPOINT TestCase specifications.
    """
    cases: list[TestCase] = []
    non_admin_identities = [
        i for i in identities if i.role.lower() != "admin" and i.name != "anonymous"
    ]

    for ep in endpoints:
        if not ep.is_privileged:
            continue

        for ident in non_admin_identities:
            cases.append(
                TestCase(
                    endpoint=ep,
                    identity_name=ident.name,
                    object_id=None,
                    category=TestCategory.PRIVILEGED_ENDPOINT,
                    expected_outcome=Outcome.DENY,
                    owner_identity=None,
                    notes=f"Privileged route BFLA probe by non-admin identity '{ident.name}'",
                )
            )

    return cases


def llm_suggested_cases(
    endpoints: list[Endpoint],
    hints: Any | None = None,
    identity_name: str = "userA",
) -> list[TestCase]:
    """Generate extra BOUNDARY test cases suggested by the LLM (GET only).

    Returns an empty list when hints is None or contains no extra_boundary_ids.
    """
    if not hints:
        return []
    extra_ids = getattr(hints, "extra_boundary_ids", None) or []
    if not extra_ids:
        return []

    cases: list[TestCase] = []
    for ep in endpoints:
        if ep.method.upper() != "GET" or not ep.is_object_level:
            continue
        for val in extra_ids:
            cases.append(
                TestCase(
                    endpoint=ep,
                    identity_name=identity_name,
                    object_id=val,
                    category=TestCategory.BOUNDARY,
                    expected_outcome=Outcome.DENY,
                    owner_identity=None,
                    notes=f"AI-suggested boundary probe with ID '{val}'",
                )
            )
    return cases


def generate_all(
    endpoints: list[Endpoint],
    identities: list[Identity],
    owned: dict[str, dict[str, list[OwnedObject]]],
    matrix_cells: list[MatrixCell],
    budget: int = 150,
    hints: Any | None = None,
) -> GenerationResult:
    """Generate a prioritized, deduplicated, budget-capped list of test cases.

    Execution order:
    1. Generates cases across all categories in priority sequence.
    2. Deduplicates on (operation_id/method+path, identity_name, object_id, category).
    3. Truncates to budget based on risk prioritization score, preserving all
       CROSS_USER and PRIVILEGED_ENDPOINT cases first.

    Args:
        endpoints: Attack surface endpoints.
        identities: Configured personas.
        owned: Discovered object ownership map.
        matrix_cells: Authorization matrix cells.
        budget: Maximum number of test cases to return.
        hints: Optional AnalystHints suggested by AI.

    Returns:
        GenerationResult tuple containing (kept_cases, stats_dict).
    """
    default_ident = "userA"
    for i in identities:
        if i.name != "anonymous" and i.role.lower() != "admin":
            default_ident = i.name
            break

    # 1. Run all generators in priority order
    extra_bids = getattr(hints, "extra_boundary_ids", None) if hints else None
    raw_cases: list[TestCase] = []
    raw_cases.extend(generate_cross_user_cases(endpoints, matrix_cells))
    raw_cases.extend(generate_privileged_cases(endpoints, identities))
    raw_cases.extend(generate_adjacent_id_cases(endpoints, owned))
    raw_cases.extend(generate_boundary_cases(endpoints, default_ident, extra_boundary_ids=extra_bids))
    raw_cases.extend(generate_anonymous_cases(endpoints, owned))
    raw_cases.extend(generate_invalid_type_cases(endpoints, default_ident))
    raw_cases.extend(llm_suggested_cases(endpoints, hints=hints, identity_name=default_ident))

    # 2. Deduplicate
    seen_keys: set[tuple[str, str, str | None, str]] = set()
    deduped_cases: list[TestCase] = []
    for c in raw_cases:
        ep_key = c.endpoint.operation_id or f"{c.endpoint.method}_{c.endpoint.path}"
        key = (ep_key, c.identity_name, c.object_id, c.category.value)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped_cases.append(c)

    # 3. Categorize counts before trimming
    generated_stats: dict[str, int] = {cat.value: 0 for cat in TestCategory}
    for c in deduped_cases:
        generated_stats[c.category.value] += 1

    # 4. Partition into must-keep (CROSS_USER, PRIVILEGED_ENDPOINT) vs secondary categories
    must_keep: list[TestCase] = []
    other_cases: list[TestCase] = []
    for c in deduped_cases:
        if c.category in (TestCategory.CROSS_USER, TestCategory.PRIVILEGED_ENDPOINT):
            must_keep.append(c)
        else:
            other_cases.append(c)

    # Sort each group by endpoint risk score descending
    must_keep.sort(key=lambda c: score_endpoint(c.endpoint), reverse=True)
    other_cases.sort(key=lambda c: score_endpoint(c.endpoint), reverse=True)

    # 5. Apply budget
    if len(must_keep) >= budget:
        kept_cases = must_keep[:budget]
    else:
        remaining_budget = budget - len(must_keep)
        kept_cases = must_keep + other_cases[:remaining_budget]

    kept_stats: dict[str, int] = {cat.value: 0 for cat in TestCategory}
    for c in kept_cases:
        kept_stats[c.category.value] += 1

    stats: dict[str, Any] = {
        "generated": generated_stats,
        "kept": kept_stats,
        "total_generated": len(deduped_cases),
        "total_kept": len(kept_cases),
        "budget": budget,
    }

    return GenerationResult(cases=kept_cases, stats=stats)
