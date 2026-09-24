"""Vulnerability reproduction engine and confidence refinement.

Empirically re-validates detected findings by repeating attack probes against the target,
updating finding confidence scores and downgrading unverified findings gracefully.
"""

import asyncio
import logging
from typing import Any

from app.engine.context import ScanContext
from app.engine.differential import compare, is_success
from app.engine.risk import compute_confidence
from app.models import Finding, Severity

logger = logging.getLogger(__name__)

SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

DOWNGRADE_MAP: dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
    Severity.INFO: Severity.INFO,
}


async def reproduce_finding(
    finding: Finding,
    ctx: ScanContext,
    attempts: int = 2,
) -> Finding:
    """Re-execute a finding's attack probe to empirically verify vulnerability reproduction.

    Args:
        finding: Vulnerability Finding to verify.
        ctx: Active ScanContext.
        attempts: Number of reproduction attempts to execute.

    Returns:
        Updated Finding with refined confidence, reproduction metadata, or severity downgrade.
    """
    if not finding.evidence:
        return finding

    req = finding.evidence.request
    identity_name = finding.evidence.identity
    identity = ctx.identity(identity_name)

    orig_status = finding.evidence.actual_status
    reproduced_count = 0
    latest_diff = None

    json_payload = req.body if isinstance(req.body, dict) else None

    for attempt_idx in range(attempts):
        if attempt_idx > 0:
            await asyncio.sleep(0.05)

        try:
            _, new_resp = await ctx.executor.execute(
                method=req.method,
                url=req.url,
                identity=identity,
                json_body=json_payload,
            )

            latest_diff = compare(
                baseline=finding.evidence.baseline_response,
                attack=new_resp,
                attacker=identity,
                requested_object_id=finding.evidence.object_id,
            )

            # Check outcome correspondence:
            # 1. Status code matches exact or status code class matches
            # 2. Not a soft error / empty body
            # 3. Flaw condition reproduces
            status_matches = (
                new_resp.status == orig_status
                or (is_success(new_resp.status) and is_success(orig_status))
            )

            if status_matches and not latest_diff.attack_body_is_error:
                reproduced_count += 1

        except Exception as exc:
            logger.debug("Reproduction attempt failed with exception: %s", exc)
            continue

    is_reproduced = reproduced_count > 0

    # Refine confidence score
    orig_conf = finding.confidence
    finding.confidence = compute_confidence(
        diff=latest_diff,
        reproduced=is_reproduced,
        reproduction_count=reproduced_count,
        base_confidence=orig_conf,
    )

    # Record reproduction details in response_diff
    finding.evidence.response_diff["reproduction"] = {
        "attempts": attempts,
        "reproduced": reproduced_count,
    }

    # If 0 attempts reproduced, downgrade severity by one level (never drop completely)
    if not is_reproduced:
        finding.severity = DOWNGRADE_MAP.get(finding.severity, Severity.INFO)
        finding.evidence.response_diff["downgraded"] = True

    return finding


async def reproduce_top_findings(
    findings: list[Finding],
    ctx: ScanContext,
    top_n: int = 8,
) -> list[Finding]:
    """Reproduce the top N findings prioritized by severity and initial confidence.

    Respects scanning request budget by focusing reproduction effort on high-impact flaws.

    Args:
        findings: Complete list of candidate findings.
        ctx: Active ScanContext.
        top_n: Maximum number of highest-priority findings to reproduce.

    Returns:
        Updated findings list.
    """
    if not findings:
        return []

    # Sort descending by severity rank then confidence
    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_RANK.get(f.severity, 0), f.confidence),
        reverse=True,
    )

    top_to_reproduce = sorted_findings[:top_n]
    skipped = sorted_findings[top_n:]

    for finding in top_to_reproduce:
        await reproduce_finding(finding, ctx)

    if skipped:
        ctx.notes.append(
            f"reproduction skipped for {len(skipped)} lower-priority findings (top_n={top_n})"
        )

    return sorted_findings
