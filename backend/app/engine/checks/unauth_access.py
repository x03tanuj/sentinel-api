"""Broken Authentication / Unauthenticated Access security check (OWASP API2:2023).

Validates that endpoints declaring authentication in their OpenAPI specification strictly
enforce authentication barriers and reject anonymous callers with HTTP 401.
"""

import logging
from typing import Any

from app.engine.checks.base import BaseCheck, register_check
from app.engine.checks.common import make_finding, provisional_severity
from app.engine.context import ScanContext
from app.engine.differential import compare, is_denied, is_not_found, is_success
from app.engine.errors import BudgetExceededError, TargetUnreachableError
from app.engine.http_executor import build_url
from app.models import Endpoint, Finding, RequestRecord, ResponseRecord

logger = logging.getLogger(__name__)

UTILITY_PATH_PREFIXES = ("/health", "/metrics", "/_reset", "/docs", "/redoc", "/openapi.json")


class UnauthAccessCheck(BaseCheck):
    """Detects missing authentication enforcement on endpoints that declare requires_auth."""

    name: str = "unauth_access"
    owasp_id: str = "API2:2023"
    description: str = (
        "Validates that endpoints declaring authentication in their OpenAPI contract reject "
        "anonymous/unauthenticated requests with HTTP 401."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        """Execute unauthenticated access checks across all auth-required GET routes."""
        findings: list[Finding] = []
        anonymous_ident = ctx.identity_manager.get("anonymous")

        non_get_unauth: list[str] = []

        for ep in ctx.endpoints:
            if not ep.requires_auth:
                continue

            # Skip standard utility routes
            if any(ep.path.startswith(prefix) for prefix in UTILITY_PATH_PREFIXES):
                continue

            if ep.method.upper() != "GET":
                non_get_unauth.append(f"{ep.method} {ep.path}")
                continue

            object_id: str | None = None
            if ep.path_params:
                # Find representative object ID from owned objects
                if ep.resource and ep.resource in ctx.owned:
                    for id_name, res_map in ctx.owned.items():
                        if ep.resource in res_map and res_map[ep.resource]:
                            object_id = res_map[ep.resource][0].object_id
                            break

                if not object_id:
                    for case in ctx.cases:
                        if case.endpoint.path == ep.path and case.object_id:
                            object_id = case.object_id
                            break

                if not object_id:
                    ctx.notes.append(f"skipped unauth check for {ep.path}: no representative object id")
                    continue

            path_params = {ep.path_params[0]: object_id} if (ep.path_params and object_id) else None
            url = build_url(ctx.base_url, ep.path, path_params)

            try:
                req_rec, resp_rec = await ctx.executor.execute(
                    method="GET",
                    url=url,
                    identity=anonymous_ident,
                )
            except BudgetExceededError:
                ctx.notes.append("unauth_access check stopped: request budget exceeded")
                return findings
            except TargetUnreachableError as exc:
                ctx.notes.append(f"unauth_access target unreachable for {ep.path}: {exc}")
                continue
            except Exception as exc:
                ctx.notes.append(f"unauth_access error on {ep.path}: {type(exc).__name__}")
                continue

            # 401 or 403 are expected safe outcomes
            if is_denied(resp_rec.status) or is_not_found(resp_rec.status):
                continue

            if is_success(resp_rec.status):
                diff = compare(
                    baseline=None,
                    attack=resp_rec,
                    attacker=None,
                    requested_object_id=object_id,
                )

                if diff.attack_body_is_error:
                    continue

                confidence = 0.90 if not diff.attack_body_empty else 0.60
                if confidence < ctx.settings.MIN_REPORT_CONFIDENCE:
                    continue

                severity = provisional_severity(
                    "unauth_access",
                    "GET",
                    diff_result=diff,
                    has_data=not diff.attack_body_empty,
                )
                finding = make_finding(
                    check="unauth_access",
                    endpoint=ep,
                    title=f"Unauthenticated Access Permitted on {ep.path}",
                    confidence=confidence,
                    explanation=(
                        f"Endpoint '{ep.path}' declares authentication requirements in the OpenAPI specification, "
                        f"but responded with HTTP {resp_rec.status} to anonymous requests without a valid token. "
                        f"This indicates a specification/implementation mismatch where authentication is not enforced."
                    ),
                    fix_hint=(
                        "Enforce authentication middleware or route dependencies requiring a valid "
                        "Authorization header. Return HTTP 401 Unauthorized when credentials are missing or invalid."
                    ),
                    identity_name="anonymous",
                    request=req_rec,
                    attack_response=resp_rec,
                    baseline_response=None,
                    diff_result=diff,
                    object_id=object_id,
                    expected_status=401,
                    severity=severity,
                    owasp_id=self.owasp_id,
                )
                findings.append(finding)

        if non_get_unauth:
            ctx.notes.append(
                f"unauth check: non-GET endpoints not tested anonymously: {', '.join(sorted(non_get_unauth))}"
            )

        return findings


# Register the check
register_check(UnauthAccessCheck())
