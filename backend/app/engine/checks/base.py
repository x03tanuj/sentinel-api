"""Base abstract class and execution harness for security check modules."""

from abc import ABC, abstractmethod
import asyncio
import logging
from typing import Any

from app.engine.context import ScanContext
from app.models import Finding

logger = logging.getLogger(__name__)


class BaseCheck(ABC):
    """Abstract base class for all SentinelAPI security check modules."""

    name: str = ""
    owasp_id: str = ""
    description: str = ""

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[Finding]:
        """Execute the security check against the active scan context.

        Args:
            ctx: Active ScanContext containing endpoints, identities, and executor.

        Returns:
            List of detected security findings.
        """
        pass


# Global check registry populated by check implementations
CHECKS: dict[str, BaseCheck] = {}


def register_check(check: BaseCheck) -> None:
    """Register a security check instance in the global registry."""
    CHECKS[check.name] = check


async def run_checks(
    ctx: ScanContext,
    enabled: list[str] | None = None,
    on_check_done: Any = None,
) -> list[Finding]:
    """Execute enabled security checks with concurrency controls, timeouts, and deduplication.

    Safety:
    1. Checks execute concurrently EXCEPT 'rate_limit', which runs last and alone
       to prevent request bursts from skewing or locking out concurrent test personas.
    2. Exceptions in any check are caught, recorded as notes, and never kill the scan.
    3. Findings below MIN_REPORT_CONFIDENCE are dropped and tallied.
    4. Duplicate findings on (check, method, path, identity) are aggregated into a single
       Finding with all affected object IDs recorded in evidence.

    Args:
        ctx: Active ScanContext.
        enabled: Optional list of check names to execute; defaults to all registered checks.
        on_check_done: Optional callback invoked when each check completes execution.

    Returns:
        Aggregated, confidence-filtered list of Findings.
    """
    check_names = enabled or list(CHECKS.keys())
    active_checks = [CHECKS[name] for name in check_names if name in CHECKS]

    concurrent_checks = [c for c in active_checks if c.name != "rate_limit"]
    rate_limit_checks = [c for c in active_checks if c.name == "rate_limit"]

    raw_findings: list[Finding] = []

    async def _safe_run(check: BaseCheck) -> list[Finding]:
        try:
            return await asyncio.wait_for(
                check.run(ctx),
                timeout=float(ctx.settings.CHECK_TIMEOUT_SECONDS),
            )
        except asyncio.TimeoutError:
            ctx.notes.append(f"check_error:{check.name}:TimeoutError")
            logger.warning("Check %s timed out after %ds", check.name, ctx.settings.CHECK_TIMEOUT_SECONDS)
            return []
        except Exception as exc:
            ctx.notes.append(f"check_error:{check.name}:{type(exc).__name__}")
            logger.exception("Check %s crashed: %s", check.name, exc)
            return []
        finally:
            if on_check_done:
                try:
                    cb = on_check_done(check.name)
                    if asyncio.iscoroutine(cb):
                        await cb
                except Exception as cb_exc:
                    logger.debug("on_check_done callback error for %s: %s", check.name, cb_exc)

    # 1. Run non-rate-limit checks concurrently
    if concurrent_checks:
        results = await asyncio.gather(*[_safe_run(c) for c in concurrent_checks])
        for f_list in results:
            raw_findings.extend(f_list)

    # 2. Run rate-limit check isolated and last
    for r_check in rate_limit_checks:
        r_findings = await _safe_run(r_check)
        raw_findings.extend(r_findings)

    # 3. Filter by MIN_REPORT_CONFIDENCE
    min_conf = ctx.settings.MIN_REPORT_CONFIDENCE
    qualified_findings: list[Finding] = []
    dropped_count = 0

    for f in raw_findings:
        if f.confidence >= min_conf:
            qualified_findings.append(f)
        else:
            dropped_count += 1

    if dropped_count > 0:
        ctx.notes.append(f"{dropped_count} findings dropped below confidence threshold {min_conf}")

    # 4. Aggregate duplicates: (check, method, path, attacker identity)
    aggregated: dict[tuple[str, str, str, str], Finding] = {}

    for f in qualified_findings:
        ident_name = f.evidence.identity if f.evidence else "unknown"
        key = (f.check, f.method.upper(), f.endpoint, ident_name)

        if key not in aggregated:
            # Initialize affected_objects list in evidence response_diff
            if f.evidence:
                f.evidence.response_diff["affected_objects"] = []
                if f.evidence.object_id:
                    f.evidence.response_diff["affected_objects"].append(f.evidence.object_id)
            aggregated[key] = f
        else:
            existing = aggregated[key]
            # Preserve the higher confidence finding and maintain all affected object IDs
            all_affected: list[str] = []
            if existing.evidence and "affected_objects" in existing.evidence.response_diff:
                all_affected.extend(existing.evidence.response_diff["affected_objects"])
            if f.evidence and f.evidence.object_id and f.evidence.object_id not in all_affected:
                all_affected.append(f.evidence.object_id)

            chosen = f if f.confidence > existing.confidence else existing
            if chosen.evidence:
                chosen.evidence.response_diff["affected_objects"] = sorted(list(set(all_affected)))
            aggregated[key] = chosen

    return list(aggregated.values())


async def run_checks_with_reproduction(
    ctx: ScanContext,
    enabled: list[str] | None = None,
    top_n: int = 8,
    on_check_done: Any = None,
) -> list[Finding]:
    """Execute enabled security checks and empirically reproduce top-priority findings.

    Args:
        ctx: Active ScanContext.
        enabled: Optional list of check names to execute.
        top_n: Maximum number of top findings to empirically reproduce.
        on_check_done: Optional callback invoked when each check completes execution.

    Returns:
        List of finalized findings with reproduction evidence and refined confidence scores.
    """
    from app.engine.reproduce import reproduce_top_findings
    from app.engine.checks.bola import cleanup_created

    findings = await run_checks(ctx, enabled=enabled, on_check_done=on_check_done)
    try:
        return await reproduce_top_findings(findings, ctx, top_n=top_n)
    finally:
        await cleanup_created(ctx)

