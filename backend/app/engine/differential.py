"""Differential analysis engine and response comparison for SentinelAPI.

Performs pure, offline comparison of baseline vs attack HTTP responses,
calculating structural similarity, owner discrepancy, and classified sensitive data exposure.
"""

import difflib
import re
from typing import Any

from pydantic import BaseModel, Field

from app.engine.discovery import extract_id
from app.engine.redaction import mask_value
from app.models import Identity, ResponseRecord

VOLATILE_KEYS: set[str] = {
    "timestamp",
    "created_at",
    "updated_at",
    "request_id",
    "trace_id",
    "etag",
    "nonce",
    "iat",
    "exp",
    "server_time",
}

SENSITIVE_FIELD_TIERS: dict[str, set[str]] = {
    "SECRET": {
        "password",
        "passwd",
        "password_hash",
        "hash",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "api_key",
        "apikey",
        "private_key",
        "ssn",
        "social_security",
        "card",
        "card_number",
        "cvv",
        "iban",
    },
    "PERSONAL": {
        "email",
        "phone",
        "dob",
        "birth",
        "address",
        "salary",
    },
    "LOW": {
        "role",
        "is_admin",
        "permissions",
        "internal_id",
    },
}

OWNER_FIELD_NAMES: set[str] = {
    "user_id",
    "userid",
    "owner_id",
    "ownerid",
    "created_by",
    "author_id",
    "account_id",
    "customer_id",
}


def classify_field(name: str) -> str | None:
    """Classify a field name into a sensitivity tier (SECRET, PERSONAL, LOW) or None.

    Splits camelCase, snake_case, and kebab-case tokens to avoid false positives
    (e.g. 'passenger' and 'compass' must not match 'pass...').

    Args:
        name: Property key or field name.

    Returns:
        Tier string ('SECRET', 'PERSONAL', 'LOW') or None.
    """
    if not name:
        return None

    # Split camelCase: passwordHash -> password Hash
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)
    # Split separators
    tokens = [t.lower() for t in re.split(r"[_\-\s]+", s) if t]
    normalized_snake = "_".join(tokens)

    # Check whole normalized string first
    for tier, keys in SENSITIVE_FIELD_TIERS.items():
        if normalized_snake in keys:
            return tier

    # Check individual token matches
    for tier, keys in SENSITIVE_FIELD_TIERS.items():
        for tok in tokens:
            if tok in keys:
                return tier

    return None


def flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Recursively flatten a JSON data structure into path -> leaf value dictionary.

    Volatile keys (e.g. timestamps, request IDs) are automatically dropped.

    Args:
        obj: Dict, list, or primitive leaf value.
        prefix: Current key path prefix.

    Returns:
        Flattened dictionary mapping leaf paths to values.
    """
    flat: dict[str, Any] = {}

    if isinstance(obj, dict):
        for k, v in obj.items():
            k_str = str(k)
            if k_str.strip().lower() in VOLATILE_KEYS:
                continue
            path = f"{prefix}.{k_str}" if prefix else k_str
            flat.update(flatten(v, path))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            path = f"{prefix}.{idx}" if prefix else str(idx)
            flat.update(flatten(item, path))
    else:
        if prefix:
            flat[prefix] = obj

    return flat


class DiffResult(BaseModel):
    """Calculated differential comparison between baseline and attack responses."""

    status_changed: bool = Field(..., description="True if attack HTTP status differs from baseline")
    baseline_status: int | None = Field(default=None, description="Baseline HTTP status code")
    attack_status: int = Field(..., description="Attack probe HTTP status code")
    body_similarity: float = Field(default=0.0, description="Payload similarity score between 0.0 and 1.0")
    schema_similarity: float = Field(default=0.0, description="Structural key-path similarity between 0.0 and 1.0")
    same_object_id: bool | None = Field(default=None, description="True if response object ID matches requested ID")
    owner_id_differs: bool | None = Field(default=None, description="True if response owner ID differs from attacker ID")
    sensitive_fields_exposed: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Mapping of sensitivity tier to list of exposed field names",
    )
    size_ratio: float = Field(default=1.0, description="Ratio of attack response size to baseline size")
    changed_fields: list[str] = Field(default_factory=list, description="List of key paths added or modified")
    attack_body_empty: bool = Field(default=False, description="True if attack payload is empty or null")
    attack_body_is_error: bool = Field(default=False, description="True if attack payload represents a soft error")


def is_success(status: int) -> bool:
    """Return True if HTTP status is within the 2xx success range."""
    return 200 <= status <= 299


def is_denied(status: int) -> bool:
    """Return True if HTTP status represents explicit authorization denial (401 or 403)."""
    return status in (401, 403)


def is_not_found(status: int) -> bool:
    """Return True if HTTP status is 404 Not Found."""
    return status == 404


def _is_error_body(body: Any) -> bool:
    """Determine whether a 2xx or non-2xx payload is actually a structured error response."""
    if not isinstance(body, dict) or not body:
        return False
    if body.get("success") is False:
        return True
    error_key_candidates = {"error", "errors", "detail", "message", "msg", "status_code"}
    lower_keys = {k.strip().lower() for k in body.keys()}
    return lower_keys.issubset(error_key_candidates)


def _find_owner_id(body: Any) -> str | None:
    """Search top-level and one-level-nested dicts for an owner identifier."""
    if isinstance(body, dict):
        for k, v in body.items():
            if k.lower() in OWNER_FIELD_NAMES and v is not None:
                return str(v)
        # Check one-level nested
        for v in body.values():
            if isinstance(v, dict):
                for nk, nv in v.items():
                    if nk.lower() in OWNER_FIELD_NAMES and nv is not None:
                        return str(nv)
    return None


def _find_field_values(body: Any, target_field: str) -> list[str]:
    """Collect string representations of all values matching target_field."""
    found: list[str] = []
    if isinstance(body, dict):
        for k, v in body.items():
            if k == target_field:
                found.append(str(v))
            elif isinstance(v, (dict, list)):
                found.extend(_find_field_values(v, target_field))
    elif isinstance(body, list):
        for item in body:
            found.extend(_find_field_values(item, target_field))
    return found


def compare(
    baseline: ResponseRecord | None,
    attack: ResponseRecord,
    attacker: Identity | None = None,
    requested_object_id: str | None = None,
) -> DiffResult:
    """Compare an attack response against baseline to evaluate authorization failure.

    Calculates body and schema similarity, checks for soft errors or empty bodies,
    determines if the returned object matches the victim's object, and checks if the owner
    differs from the probing identity.

    Args:
        baseline: Legitimate baseline ResponseRecord (or None).
        attack: Probing attack ResponseRecord.
        attacker: Identity executing the probe.
        requested_object_id: The specific object ID requested in the probe.

    Returns:
        DiffResult model summarizing discrepancy signals.
    """
    status_changed = (baseline is not None) and (baseline.status != attack.status)
    baseline_status = baseline.status if baseline else None
    attack_status = attack.status

    # 1. Attack body emptiness
    attack_body_empty = (
        attack.body is None
        or attack.body == ""
        or attack.body == {}
        or attack.body == []
        or attack.size <= 2
    )

    # 2. Attack body is error
    attack_body_is_error = _is_error_body(attack.body)

    # 3. Same object ID check
    same_object_id: bool | None = None
    if requested_object_id is not None and isinstance(attack.body, dict):
        discovered_id = extract_id(attack.body)
        if discovered_id is not None:
            same_object_id = str(discovered_id) == str(requested_object_id)

    # 4. Owner ID differs check
    owner_id_differs: bool | None = None
    found_owner = _find_owner_id(attack.body)
    if found_owner is not None and attacker is not None and attacker.user_id is not None:
        owner_id_differs = str(found_owner) != str(attacker.user_id)

    # 5. Sensitive fields exposed in attack body
    sensitive_exposed: dict[str, list[str]] = {}
    if isinstance(attack.body, (dict, list)):
        flat_attack = flatten(attack.body)
        for path in flat_attack.keys():
            leaf = path.split(".")[-1].split("[")[0]
            tier = classify_field(leaf)
            if tier:
                if tier not in sensitive_exposed:
                    sensitive_exposed[tier] = []
                if leaf not in sensitive_exposed[tier]:
                    sensitive_exposed[tier].append(leaf)

    # 6. Similarity calculation
    body_sim = 0.0
    schema_sim = 0.0
    changed: list[str] = []

    if baseline is not None and baseline.body is not None:
        if isinstance(baseline.body, (dict, list)) and isinstance(attack.body, (dict, list)):
            base_flat = flatten(baseline.body)
            attack_flat = flatten(attack.body)

            base_keys = set(base_flat.keys())
            attack_keys = set(attack_flat.keys())

            union_keys = base_keys | attack_keys
            inter_keys = base_keys & attack_keys

            schema_sim = len(inter_keys) / len(union_keys) if union_keys else 1.0

            matching_values = sum(1 for k in inter_keys if base_flat[k] == attack_flat[k])
            body_sim = matching_values / len(union_keys) if union_keys else 1.0

            diff_keys = (attack_keys - base_keys) | {k for k in inter_keys if base_flat[k] != attack_flat[k]}
            changed = sorted(list(diff_keys))
        else:
            b_text = str(baseline.body)[:20000]
            a_text = str(attack.body)[:20000]
            matcher = difflib.SequenceMatcher(None, b_text, a_text)
            body_sim = matcher.ratio()
            schema_sim = body_sim
            changed = [] if body_sim == 1.0 else ["raw_text"]

    size_ratio = float(attack.size) / float(baseline.size) if (baseline and baseline.size > 0) else 1.0

    return DiffResult(
        status_changed=status_changed,
        baseline_status=baseline_status,
        attack_status=attack_status,
        body_similarity=round(body_sim, 4),
        schema_similarity=round(schema_sim, 4),
        same_object_id=same_object_id,
        owner_id_differs=owner_id_differs,
        sensitive_fields_exposed=sensitive_exposed,
        size_ratio=round(size_ratio, 3),
        changed_fields=changed,
        attack_body_empty=attack_body_empty,
        attack_body_is_error=attack_body_is_error,
    )


def summarize_diff_for_evidence(diff: DiffResult, attack: ResponseRecord) -> dict[str, Any]:
    """Generate a sanitized response_diff dictionary safe for Evidence serialization.

    Includes field names, similarity scores, and masked sample values (using mask_value),
    guaranteeing that raw secrets (e.g. SSNs, password hashes) never enter evidence artifacts.

    Args:
        diff: DiffResult model from compare().
        attack: Probing attack ResponseRecord.

    Returns:
        Scrubbed evidence dictionary.
    """
    masked_sensitive_samples: dict[str, list[str]] = {}
    for tier, fields in diff.sensitive_fields_exposed.items():
        masked_samples: list[str] = []
        for f in fields:
            vals = _find_field_values(attack.body, f)
            if vals:
                masked_samples.append(f"{f}: {mask_value(vals[0])}")
            else:
                masked_samples.append(f)
        masked_sensitive_samples[tier] = masked_samples

    return {
        "status_changed": diff.status_changed,
        "body_similarity": diff.body_similarity,
        "schema_similarity": diff.schema_similarity,
        "same_object_id": diff.same_object_id,
        "owner_id_differs": diff.owner_id_differs,
        "changed_fields_count": len(diff.changed_fields),
        "changed_fields_sample": diff.changed_fields[:10],
        "sensitive_fields_masked": masked_sensitive_samples,
        "attack_body_is_error": diff.attack_body_is_error,
        "attack_body_empty": diff.attack_body_empty,
    }
