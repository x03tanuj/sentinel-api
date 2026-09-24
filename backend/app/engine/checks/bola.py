"""Broken Object Level Authorization (BOLA / IDOR — OWASP API1:2023) check module."""

import logging
from typing import Any

from app.engine.auth_matrix import Outcome
from app.engine.checks.base import BaseCheck, register_check
from app.engine.checks.common import make_finding
from app.engine.context import ScanContext
from app.engine.differential import compare, is_success
from app.engine.discovery import discover_via_creation
from app.engine.runner import _build_case_url, run_cases
from app.engine.test_generator import TestCategory
from app.models import Finding, Severity

logger = logging.getLogger(__name__)


async def cleanup_created(ctx: ScanContext) -> None:
    """Best-effort deletion of scanner-created test artifacts."""
    for item in list(ctx.created_objects):
        if item.get("cleaned"):
            continue
        resource = item["resource"]
        object_id = item["object_id"]
        owner_name = item["owner"]
        del_ep = ctx.find_endpoint("DELETE", resource=resource, object_level=True)
        if del_ep:
            try:
                owner_ident = ctx.identity(owner_name)
                del_url = _build_case_url(ctx.base_url, del_ep, object_id)
                await ctx.executor.execute("DELETE", del_url, identity=owner_ident)
                item["cleaned"] = True
            except Exception as exc:
                ctx.notes.append(f"cleanup error for {resource} {object_id}: {type(exc).__name__}")


class BolaCheck(BaseCheck):
    """Detects Broken Object Level Authorization across read and write operations."""

    name: str = "bola"
    owasp_id: str = "API1:2023"
    description: str = "Broken Object Level Authorization (BOLA/IDOR)"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        try:
            # ==========================================
            # 1. READ BOLA (GET Probes on Test Cases)
            # ==========================================
            read_cases = [
                c for c in ctx.cases
                if c.category in (TestCategory.CROSS_USER, TestCategory.ADJACENT_ID)
                and c.endpoint.method.upper() == "GET"
            ]

            results = await run_cases(ctx, read_cases)

            for res in results:
                # Skip if cross-user case has no baseline (unprovable)
                if res.baseline_response is None and res.case.category == TestCategory.CROSS_USER:
                    continue

                attacker = ctx.identity(res.case.identity_name)
                # Administrative identities legitimately have access across objects; BOLA applies to non-admin roles
                if attacker and attacker.role.lower() == "admin":
                    continue
                diff = compare(
                    baseline=res.baseline_response,
                    attack=res.response,
                    attacker=attacker,
                    requested_object_id=res.case.object_id,
                )

                # Check for vulnerable read
                if (
                    res.case.expected_outcome == Outcome.DENY
                    and is_success(res.response.status)
                    and not diff.attack_body_is_error
                    and not diff.attack_body_empty
                ):
                    confidence = 0.3
                    if diff.body_similarity >= 0.9 and diff.owner_id_differs is True:
                        confidence = 0.95
                    elif diff.body_similarity >= 0.6 and (diff.owner_id_differs is True or diff.same_object_id is True):
                        confidence = 0.85
                    elif diff.same_object_id is True and res.baseline_response is None:
                        confidence = 0.60

                    if confidence >= ctx.settings.MIN_REPORT_CONFIDENCE:
                        findings.append(
                            make_finding(
                                check=self.name,
                                endpoint=res.case.endpoint,
                                title=f"Broken Object Level Authorization (BOLA/IDOR) on {res.case.endpoint.path}",
                                confidence=confidence,
                                explanation=(
                                    f"Identity '{res.case.identity_name}' successfully accessed object "
                                    f"'{res.case.object_id}' owned by '{res.case.owner_identity or 'another user'}' "
                                    f"with HTTP {res.response.status} (Similarity: {diff.body_similarity:.2f})."
                                ),
                                fix_hint="Verify user authorization against object ownership before returning resource records.",
                                identity_name=res.case.identity_name,
                                request=res.request,
                                attack_response=res.response,
                                baseline_response=res.baseline_response,
                                diff_result=diff,
                                object_id=res.case.object_id,
                                expected_status=403,
                                severity=Severity.HIGH,
                                owasp_id=self.owasp_id,
                            )
                        )

            # ==========================================
            # 2. WRITE BOLA (PUT/PATCH/DELETE Probes)
            # ==========================================
            non_admins = [
                i for i in ctx.identity_manager.all()
                if i.role.lower() != "admin" and i.name != "anonymous"
            ]

            # Iterate over ordered pairs of distinct non-admin identities
            for i, victim in enumerate(non_admins):
                for attacker in non_admins:
                    if victim.name == attacker.name:
                        continue

                    # Find resources with sample bodies and creation endpoints
                    for resource, sample_body in ctx.sample_bodies.items():
                        post_ep = ctx.find_endpoint("POST", resource=resource, object_level=False)
                        put_ep = ctx.find_endpoint("PUT", resource=resource, object_level=True)
                        del_ep = ctx.find_endpoint("DELETE", resource=resource, object_level=True)
                        get_ep = ctx.find_endpoint("GET", resource=resource, object_level=True)

                        if not post_ep:
                            continue

                        # --- A. PUT / PATCH Write BOLA ---
                        if put_ep:
                            # 1. Victim creates fresh object
                            created = await discover_via_creation(
                                ctx.endpoints, victim, ctx.executor, {resource: sample_body}, base_url=ctx.base_url
                            )
                            if created:
                                obj = created[0]
                                ctx.created_objects.append({
                                    "resource": resource,
                                    "object_id": obj.object_id,
                                    "owner": victim.name,
                                    "delete_endpoint": del_ep.path if del_ep else None,
                                    "cleaned": False,
                                })

                                # 2. Attacker attempts to overwrite victim's object
                                update_body = dict(sample_body)
                                put_url = _build_case_url(ctx.base_url, put_ep, obj.object_id)
                                put_req, put_resp = await ctx.executor.execute(
                                    "PUT", put_url, identity=attacker, json_body=update_body
                                )

                                if is_success(put_resp.status):
                                    # Verify mutation via victim GET
                                    diff = None
                                    confidence = 0.7
                                    if get_ep:
                                        get_url = _build_case_url(ctx.base_url, get_ep, obj.object_id)
                                        _, verify_resp = await ctx.executor.execute("GET", get_url, identity=victim)
                                        if is_success(verify_resp.status):
                                            confidence = 0.95

                                    findings.append(
                                        make_finding(
                                            check=self.name,
                                            endpoint=put_ep,
                                            title=f"Write-BOLA: Unauthorized Object Modification on {put_ep.path}",
                                            confidence=confidence,
                                            explanation=(
                                                f"Attacker '{attacker.name}' modified {resource} '{obj.object_id}' "
                                                f"owned by '{victim.name}' with HTTP {put_resp.status}."
                                            ),
                                            fix_hint="Enforce strict object ownership validation on PUT/PATCH mutation requests.",
                                            identity_name=attacker.name,
                                            request=put_req,
                                            attack_response=put_resp,
                                            object_id=obj.object_id,
                                            expected_status=403,
                                            severity=Severity.CRITICAL,
                                            owasp_id=self.owasp_id,
                                        )
                                    )

                        # --- B. DELETE Write BOLA ---
                        if del_ep:
                            # 1. Victim creates a separate fresh object for deletion test
                            del_created = await discover_via_creation(
                                ctx.endpoints, victim, ctx.executor, {resource: sample_body}, base_url=ctx.base_url
                            )
                            if del_created:
                                obj_del = del_created[0]
                                ctx.created_objects.append({
                                    "resource": resource,
                                    "object_id": obj_del.object_id,
                                    "owner": victim.name,
                                    "delete_endpoint": del_ep.path,
                                    "cleaned": False,
                                })

                                # 2. Attacker attempts deletion
                                del_url = _build_case_url(ctx.base_url, del_ep, obj_del.object_id)
                                del_req, del_resp = await ctx.executor.execute(
                                    "DELETE", del_url, identity=attacker
                                )

                                if is_success(del_resp.status):
                                    confidence = 0.6
                                    if get_ep:
                                        get_url = _build_case_url(ctx.base_url, get_ep, obj_del.object_id)
                                        _, verify_resp = await ctx.executor.execute("GET", get_url, identity=victim)
                                        if verify_resp.status == 404:
                                            confidence = 0.95
                                            # Mark as already deleted
                                            ctx.created_objects[-1]["cleaned"] = True

                                    findings.append(
                                        make_finding(
                                            check=self.name,
                                            endpoint=del_ep,
                                            title=f"Write-BOLA: Unauthorized Object Deletion on {del_ep.path}",
                                            confidence=confidence,
                                            explanation=(
                                                f"Attacker '{attacker.name}' deleted {resource} '{obj_del.object_id}' "
                                                f"owned by '{victim.name}' with HTTP {del_resp.status}."
                                            ),
                                            fix_hint="Enforce strict object ownership validation on DELETE operations.",
                                            identity_name=attacker.name,
                                            request=del_req,
                                            attack_response=del_resp,
                                            object_id=obj_del.object_id,
                                            expected_status=403,
                                            severity=Severity.CRITICAL,
                                            owasp_id=self.owasp_id,
                                        )
                                    )

        finally:
            await cleanup_created(ctx)

        return findings


register_check(BolaCheck())
