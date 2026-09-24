"""Broken Function Level Authorization (BFLA) security check (OWASP API5:2023).

Verifies that administrative/privileged endpoints strictly enforce role-based access control
and cannot be accessed by non-administrative test identities.
"""

import logging
from typing import Any

from app.engine.checks.base import BaseCheck, register_check
from app.engine.checks.common import make_finding, provisional_severity
from app.engine.context import ScanContext
from app.engine.risk import RiskInputs
from app.engine.differential import compare, is_denied, is_not_found, is_success
from app.engine.errors import BudgetExceededError, TargetUnreachableError
from app.engine.http_executor import build_url
from app.models import Endpoint, Finding, Identity, RequestRecord, ResponseRecord

logger = logging.getLogger(__name__)


class BflaCheck(BaseCheck):
    """Detects Broken Function Level Authorization vulnerabilities on privileged routes."""

    name: str = "bfla"
    owasp_id: str = "API5:2023"
    description: str = (
        "Validates that endpoints marked as privileged or administrative enforce role checks "
        "and reject requests from non-administrative identities."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """Execute BFLA checks across all privileged GET endpoints."""
        findings: list[Finding] = []

        # Find admin identity for baseline
        admin_identity: Identity | None = None
        for ident in ctx.identity_manager.list_identities():
            if ident.role.lower() == "admin":
                admin_identity = ident
                break

        # Identify non-admin identities
        non_admin_identities = [
            ident
            for ident in ctx.identity_manager.list_identities()
            if ident.name != "anonymous" and ident.role.lower() != "admin"
        ]

        if not non_admin_identities:
            ctx.notes.append("skipped BFLA: no non-admin identities available for testing")
            return findings

        # Track non-GET privileged endpoints
        non_get_privileged: list[str] = []

        for ep in ctx.endpoints:
            if not ep.is_privileged:
                continue

            if ep.method.upper() != "GET":
                non_get_privileged.append(f"{ep.method} {ep.path}")
                continue

            # Resolve object ID if path parameter is required
            object_id: str | None = None
            if ep.path_params:
                # Look for an owned object in ctx.owned across all identities
                if ep.resource and ep.resource in ctx.owned:
                    for id_name, res_map in ctx.owned.items():
                        if ep.resource in res_map and res_map[ep.resource]:
                            object_id = res_map[ep.resource][0].object_id
                            break

                if not object_id:
                    # Look in test cases
                    for case in ctx.cases:
                        if case.endpoint.path == ep.path and case.object_id:
                            object_id = case.object_id
                            break

                if not object_id:
                    ctx.notes.append(f"skipped BFLA for {ep.path}: no representative object id")
                    continue

            path_params = {ep.path_params[0]: object_id} if (ep.path_params and object_id) else None
            url = build_url(ctx.base_url, ep.path, path_params)

            # Step 1: Baseline request as admin if available
            baseline_req: RequestRecord | None = None
            baseline_resp: ResponseRecord | None = None

            if admin_identity:
                try:
                    baseline_req, baseline_resp = await ctx.executor.execute(
                        method="GET",
                        url=url,
                        identity=admin_identity,
                    )
                    if not is_success(baseline_resp.status):
                        baseline_resp = None
                except (BudgetExceededError, TargetUnreachableError):
                    raise
                except Exception as exc:
                    logger.debug("Failed to fetch admin baseline for BFLA on %s: %s", ep.path, exc)
                    baseline_resp = None

            # Step 2: Request as each non-admin persona
            for attacker in non_admin_identities:
                try:
                    attack_req, attack_resp = await ctx.executor.execute(
                        method="GET",
                        url=url,
                        identity=attacker,
                    )
                except BudgetExceededError:
                    ctx.notes.append("BFLA check stopped: request budget exceeded")
                    return findings
                except TargetUnreachableError as exc:
                    ctx.notes.append(f"BFLA target unreachable for {ep.path}: {exc}")
                    continue
                except Exception as exc:
                    ctx.notes.append(f"BFLA error for {attacker.name} on {ep.path}: {type(exc).__name__}")
                    continue

                # 401, 403, 404 are expected safe outcomes
                if is_denied(attack_resp.status) or is_not_found(attack_resp.status):
                    continue

                if is_success(attack_resp.status):
                    diff = compare(
                        baseline=baseline_resp,
                        attack=attack_resp,
                        attacker=attacker,
                        requested_object_id=object_id,
                    )

                    if diff.attack_body_is_error or diff.attack_body_empty:
                        continue

                    # Confidence calculation
                    if baseline_resp is not None and diff.body_similarity >= 0.6:
                        confidence = 0.90
                    elif baseline_resp is None and not diff.attack_body_empty:
                        confidence = 0.75
                    else:
                        confidence = 0.30

                    if confidence < ctx.settings.MIN_REPORT_CONFIDENCE:
                        continue

                    risk_inputs = RiskInputs(
                        check_name="bfla",
                        method="GET",
                        is_privileged_endpoint=True,
                        requires_auth=ep.requires_auth,
                        object_id_sequential=True if (object_id and str(object_id).isdigit()) else False,
                        diff=diff,
                        attacker_identity_role=attacker.role,
                        base_confidence=confidence,
                    )
                    finding = make_finding(
                        check="bfla",
                        endpoint=ep,
                        title=f"Broken Function Level Authorization on {ep.path}",
                        confidence=confidence,
                        explanation=(
                            f"Privileged endpoint '{ep.path}' was successfully accessed by non-administrative "
                            f"identity '{attacker.name}' (role: {attacker.role}) with HTTP {attack_resp.status}."
                        ),
                        fix_hint=(
                            "Enforce strict role-based access control (RBAC). Verify that the calling user possesses "
                            "administrative permissions prior to executing the operation."
                        ),
                        identity_name=attacker.name,
                        request=attack_req,
                        attack_response=attack_resp,
                        baseline_response=baseline_resp,
                        diff_result=diff,
                        object_id=object_id,
                        expected_status=403,
                        owasp_id=self.owasp_id,
                        risk_inputs=risk_inputs,
                    )
                    findings.append(finding)

        if non_get_privileged:
            ctx.notes.append(
                f"privileged non-GET endpoints not tested: {', '.join(sorted(non_get_privileged))}"
            )

        return findings


# Register the check
register_check(BflaCheck())
