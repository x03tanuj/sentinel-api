"""Excessive Data Exposure security check (OWASP API3:2023).

Detects endpoints that expose sensitive personal/credential data, leak fields beyond
the documented OpenAPI contract, or return password hashes/tokens to non-admin identities.
"""

import logging
from typing import Any

from app.engine.checks.base import BaseCheck, register_check
from app.engine.checks.common import make_finding, provisional_severity
from app.engine.context import ScanContext
from app.engine.risk import RiskInputs
from app.engine.differential import (
    DiffResult,
    classify_field,
    compare,
    flatten,
    is_success,
)
from app.engine.errors import BudgetExceededError, TargetUnreachableError
from app.engine.http_executor import build_url
from app.engine.redaction import mask_value
from app.models import Endpoint, Finding, Identity, RequestRecord, ResponseRecord, Severity

logger = logging.getLogger(__name__)


def extract_declared_properties(schema: dict[str, Any] | None) -> set[str] | None:
    """Recursively extract declared property names and paths from an OpenAPI response schema.

    Returns None if the schema is too dynamic, complex, or allows arbitrary additionalProperties.
    """
    if not schema or not isinstance(schema, dict):
        return None

    # Handle additionalProperties: true
    if schema.get("additionalProperties") is True:
        return None

    # Handle allOf
    if "allOf" in schema and isinstance(schema["allOf"], list):
        declared: set[str] = set()
        for sub in schema["allOf"]:
            sub_props = extract_declared_properties(sub)
            if sub_props is None:
                return None
            declared.update(sub_props)
        return declared

    # Handle arrays
    if schema.get("type") == "array" or "items" in schema:
        return extract_declared_properties(schema.get("items"))

    # Handle objects with properties
    if "properties" in schema and isinstance(schema["properties"], dict):
        declared = set()
        for prop_name, prop_def in schema["properties"].items():
            declared.add(prop_name)
            if isinstance(prop_def, dict):
                nested = extract_declared_properties(prop_def)
                if nested is not None:
                    for n in nested:
                        declared.add(f"{prop_name}.{n}")
        return declared

    return None


class DataExposureCheck(BaseCheck):
    """Detects excessive data exposure and contract divergence on authenticated GET routes."""

    name: str = "data_exposure"
    owasp_id: str = "API3:2023"
    description: str = (
        "Validates that endpoints do not expose undeclared fields beyond the OpenAPI schema "
        "and do not leak secret or credential fields to non-administrative callers."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """Execute excessive data exposure checks across all authenticated GET routes."""
        findings: list[Finding] = []

        # Non-admin personas only (admin responses are not evaluated)
        non_admins = [
            ident
            for ident in ctx.identity_manager.list_identities()
            if ident.name != "anonymous" and ident.role.lower() != "admin"
        ]

        if not non_admins:
            ctx.notes.append("skipped data_exposure: no non-admin identities available")
            return findings

        for ep in ctx.endpoints:
            if ep.method.upper() != "GET":
                continue
            if not ep.requires_auth:
                continue
            if ep.is_privileged:
                continue
            if not ep.response_schema:
                continue

            declared_fields = extract_declared_properties(ep.response_schema)

            for identity in non_admins:
                object_id: str | None = None
                if ep.is_object_level or ep.path_params:
                    # Look up an object owned by THIS identity
                    owned_list = ctx.owned.get(identity.name, {}).get(ep.resource or "", [])
                    if owned_list:
                        object_id = owned_list[0].object_id
                    elif identity.user_id and (ep.resource == "user" or "{id}" in ep.path):
                        object_id = str(identity.user_id)
                    else:
                        # Fallback: check any case generated for this identity
                        for case in ctx.cases:
                            if (
                                case.endpoint.path == ep.path
                                and case.identity.name == identity.name
                                and case.object_id
                            ):
                                object_id = case.object_id
                                break

                    if ep.path_params and not object_id:
                        continue

                path_params = {ep.path_params[0]: object_id} if (ep.path_params and object_id) else None
                url = build_url(ctx.base_url, ep.path, path_params)

                try:
                    req_rec, resp_rec = await ctx.executor.execute(
                        method="GET",
                        url=url,
                        identity=identity,
                    )
                except BudgetExceededError:
                    ctx.notes.append("data_exposure check stopped: request budget exceeded")
                    return findings
                except TargetUnreachableError as exc:
                    ctx.notes.append(f"data_exposure target unreachable for {ep.path}: {exc}")
                    continue
                except Exception as exc:
                    ctx.notes.append(f"data_exposure error for {identity.name} on {ep.path}: {type(exc).__name__}")
                    continue

                if not is_success(resp_rec.status) or not isinstance(resp_rec.body, (dict, list)):
                    continue

                # Analyze payload fields
                flattened = flatten(resp_rec.body)
                if not flattened:
                    continue

                undeclared_sensitive: dict[str, list[str]] = {"SECRET": [], "PERSONAL": [], "LOW": []}
                declared_secret: list[str] = []
                undeclared_general: list[str] = []

                # Determine if this response represents the caller's own record
                is_own_record = False
                if object_id and identity.user_id and str(object_id) == str(identity.user_id):
                    is_own_record = True
                elif ep.resource == "user" and identity.user_id:
                    # Check body ID
                    for k, v in flattened.items():
                        leaf = k.split(".")[-1].lower()
                        if leaf in ("id", "user_id") and str(v) == str(identity.user_id):
                            is_own_record = True
                            break

                for path_key, val in flattened.items():
                    leaf = path_key.split(".")[-1]
                    tier = classify_field(leaf)

                    # Strip list indices for schema matching: items.0.name -> items.name
                    path_no_indices = ".".join(
                        seg for seg in path_key.split(".") if not seg.isdigit()
                    )

                    is_declared = True
                    if declared_fields is not None:
                        is_declared = (
                            leaf in declared_fields
                            or path_key in declared_fields
                            or path_no_indices in declared_fields
                        )

                    if not is_declared:
                        if tier in undeclared_sensitive:
                            if leaf not in undeclared_sensitive[tier]:
                                undeclared_sensitive[tier].append(leaf)
                        else:
                            if leaf not in undeclared_general:
                                undeclared_general.append(leaf)
                    else:
                        # Declared field
                        if tier == "SECRET":
                            if leaf not in declared_secret:
                                declared_secret.append(leaf)

                # Determine findings:
                # Rule 1: Undeclared fields with SECRET or PERSONAL tier
                has_undeclared_secret = bool(undeclared_sensitive["SECRET"])
                has_undeclared_personal = bool(undeclared_sensitive["PERSONAL"])
                has_undeclared_low_only = (
                    bool(undeclared_sensitive["LOW"])
                    and not has_undeclared_secret
                    and not has_undeclared_personal
                )

                # Rule 2: SECRET-tier field present even if declared (e.g. password_hash, token)
                # Own record: flag secret credentials like password_hash, private tokens
                has_secret_credentials = bool(declared_secret)

                if has_undeclared_secret or has_undeclared_personal or has_secret_credentials:
                    exposed_tiers: dict[str, list[str]] = {}
                    all_flagged: list[str] = []

                    if has_undeclared_secret:
                        exposed_tiers["SECRET"] = undeclared_sensitive["SECRET"]
                        all_flagged.extend(undeclared_sensitive["SECRET"])
                    if declared_secret:
                        exposed_tiers.setdefault("SECRET", [])
                        for s in declared_secret:
                            if s not in exposed_tiers["SECRET"]:
                                exposed_tiers["SECRET"].append(s)
                                all_flagged.append(s)
                    if has_undeclared_personal:
                        exposed_tiers["PERSONAL"] = undeclared_sensitive["PERSONAL"]
                        all_flagged.extend(undeclared_sensitive["PERSONAL"])

                    confidence = 0.90 if ("SECRET" in exposed_tiers or "PERSONAL" in exposed_tiers) else 0.80
                    if confidence >= ctx.settings.MIN_REPORT_CONFIDENCE:
                        diff_res = DiffResult(
                            status_changed=False,
                            baseline_status=resp_rec.status,
                            attack_status=resp_rec.status,
                            body_similarity=1.0,
                            schema_similarity=1.0,
                            same_object_id=True if object_id else None,
                            owner_id_differs=False if is_own_record else None,
                            sensitive_fields_exposed=exposed_tiers,
                            size_ratio=1.0,
                            changed_fields=all_flagged,
                            attack_body_empty=False,
                            attack_body_is_error=False,
                        )

                        risk_inputs = RiskInputs(
                            check_name="data_exposure",
                            method=ep.method,
                            is_privileged_endpoint=False,
                            requires_auth=ep.requires_auth,
                            object_id_sequential=True if (object_id and str(object_id).isdigit()) else False,
                            diff=diff_res,
                            attacker_identity_role=identity.role,
                            base_confidence=confidence,
                        )
                        fields_str = ", ".join(f"'{f}'" for f in all_flagged)
                        finding = make_finding(
                            check="data_exposure",
                            endpoint=ep,
                            title=f"Excessive Data Exposure on {ep.path}",
                            confidence=confidence,
                            explanation=(
                                f"Endpoint '{ep.path}' exposes sensitive fields ({fields_str}) "
                                f"to non-admin identity '{identity.name}' beyond the declared schema or security baseline."
                            ),
                            fix_hint=(
                                "Filter response models to omit sensitive attributes (passwords, hashes, SSNs, personal records). "
                                "Ensure responses conform strictly to the declared OpenAPI schema."
                            ),
                            identity_name=identity.name,
                            request=req_rec,
                            attack_response=resp_rec,
                            baseline_response=None,
                            diff_result=diff_res,
                            object_id=object_id,
                            expected_status=resp_rec.status,
                            owasp_id=self.owasp_id,
                            risk_inputs=risk_inputs,
                        )
                        findings.append(finding)

                elif has_undeclared_low_only:
                    # LOW-tier fields alone (e.g. role) reported at most as LOW severity with confidence 0.55
                    conf = 0.55
                    if conf >= ctx.settings.MIN_REPORT_CONFIDENCE:
                        diff_res = DiffResult(
                            status_changed=False,
                            baseline_status=resp_rec.status,
                            attack_status=resp_rec.status,
                            body_similarity=1.0,
                            schema_similarity=1.0,
                            same_object_id=True if object_id else None,
                            owner_id_differs=None,
                            sensitive_fields_exposed={"LOW": undeclared_sensitive["LOW"]},
                            size_ratio=1.0,
                            changed_fields=undeclared_sensitive["LOW"],
                            attack_body_empty=False,
                            attack_body_is_error=False,
                        )
                        risk_inputs_low = RiskInputs(
                            check_name="data_exposure",
                            method=ep.method,
                            is_privileged_endpoint=False,
                            requires_auth=ep.requires_auth,
                            object_id_sequential=True if (object_id and str(object_id).isdigit()) else False,
                            diff=diff_res,
                            attacker_identity_role=identity.role,
                            base_confidence=conf,
                        )
                        finding = make_finding(
                            check="data_exposure",
                            endpoint=ep,
                            title=f"Undeclared Metadata Exposure on {ep.path}",
                            confidence=conf,
                            explanation=(
                                f"Endpoint '{ep.path}' returned undeclared low-tier metadata fields "
                                f"({', '.join(undeclared_sensitive['LOW'])}) to identity '{identity.name}'."
                            ),
                            fix_hint="Update OpenAPI response schema or filter internal metadata fields.",
                            identity_name=identity.name,
                            request=req_rec,
                            attack_response=resp_rec,
                            baseline_response=None,
                            diff_result=diff_res,
                            object_id=object_id,
                            expected_status=resp_rec.status,
                            owasp_id=self.owasp_id,
                            risk_inputs=risk_inputs_low,
                        )
                        findings.append(finding)

        return findings


# Register the check
register_check(DataExposureCheck())
