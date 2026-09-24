"""Test case runner with concurrency control, baseline caching, and safety guards."""

import asyncio
from dataclasses import dataclass
import logging
from typing import Any

from app.engine.context import ScanContext
from app.engine.errors import BudgetExceededError, TargetUnreachableError
from app.engine.http_executor import build_url
from app.engine.test_generator import TestCase
from app.models import Endpoint, RequestRecord, ResponseRecord

logger = logging.getLogger(__name__)


@dataclass
class CaseResult:
    """Execution outcome of a single test case probe."""

    case: TestCase
    request: RequestRecord
    response: ResponseRecord
    baseline_response: ResponseRecord | None = None
    baseline_request: RequestRecord | None = None


def _build_case_url(base_url: str, endpoint: Endpoint, object_id: str | None) -> str:
    """Safely build target URL for a test case substituting path parameters."""
    if endpoint.path_params and object_id is not None:
        param_name = endpoint.path_params[0]
        return build_url(base_url, endpoint.path, path_params={param_name: object_id})
    return build_url(base_url, endpoint.path)


async def run_cases(ctx: ScanContext, cases: list[TestCase]) -> list[CaseResult]:
    """Execute a list of test cases adhering to read-only safety rules and concurrency limits.

    Safety:
    1. Executes ONLY GET cases against seed/discovered objects.
    2. Non-GET cases are deferred to dedicated write checks on scanner-created objects.
    3. Concurrency is throttled by asyncio.Semaphore(CASE_CONCURRENCY).
    4. Legitimate baselines are fetched at most once per (endpoint, owner, object_id) and cached.

    Args:
        ctx: Active ScanContext.
        cases: List of TestCase specifications to execute.

    Returns:
        List of completed CaseResult models.
    """
    # 1. Filter read-only GET cases
    get_cases = [c for c in cases if c.endpoint.method.upper() == "GET"]
    deferred_count = len(cases) - len(get_cases)
    if deferred_count > 0:
        ctx.notes.append(f"{deferred_count} non-GET cases deferred to write-check")

    results: list[CaseResult] = []
    sem = asyncio.Semaphore(max(1, ctx.settings.CASE_CONCURRENCY))

    # Cache: (endpoint_key, owner_identity, object_id) -> (baseline_req, baseline_resp)
    baseline_cache: dict[tuple[str, str, str | None], tuple[RequestRecord | None, ResponseRecord | None]] = {}
    baseline_lock = asyncio.Lock()
    budget_exhausted = False

    async def _execute_single_case(c: TestCase) -> CaseResult | None:
        nonlocal budget_exhausted
        if budget_exhausted:
            return None

        async with sem:
            if budget_exhausted:
                return None

            ep_key = c.endpoint.operation_id or f"{c.endpoint.method}_{c.endpoint.path}"
            baseline_req: RequestRecord | None = None
            baseline_resp: ResponseRecord | None = None

            # Fetch or retrieve baseline if owner identity is known and distinct
            if (
                c.owner_identity
                and c.owner_identity != "shared"
                and c.owner_identity != "anonymous"
                and c.object_id is not None
            ):
                b_key = (ep_key, c.owner_identity, c.object_id)
                async with baseline_lock:
                    if b_key not in baseline_cache:
                        try:
                            owner_ident = ctx.identity(c.owner_identity)
                            b_url = _build_case_url(ctx.base_url, c.endpoint, c.object_id)
                            req_b, resp_b = await ctx.executor.execute("GET", b_url, identity=owner_ident)
                            if 200 <= resp_b.status <= 299:
                                baseline_cache[b_key] = (req_b, resp_b)
                            else:
                                baseline_cache[b_key] = (req_b, None)
                        except BudgetExceededError:
                            budget_exhausted = True
                            ctx.notes.append("Budget exceeded during baseline acquisition; stopping runner")
                            baseline_cache[b_key] = (None, None)
                        except Exception as exc:
                            logger.debug("Failed to fetch baseline for %s: %s", b_key, exc)
                            baseline_cache[b_key] = (None, None)

                    baseline_req, baseline_resp = baseline_cache[b_key]

            if budget_exhausted:
                return None

            # Execute attack probe
            target_url = _build_case_url(ctx.base_url, c.endpoint, c.object_id)
            attacker_ident = ctx.identity(c.identity_name)

            try:
                req_rec, resp_rec = await ctx.executor.execute("GET", target_url, identity=attacker_ident)
                return CaseResult(
                    case=c,
                    request=req_rec,
                    response=resp_rec,
                    baseline_response=baseline_resp,
                    baseline_request=baseline_req,
                )
            except BudgetExceededError:
                budget_exhausted = True
                ctx.notes.append(f"Budget exceeded after {ctx.executor.requests_sent} requests; stopping runner")
                return None
            except TargetUnreachableError as exc:
                ctx.notes.append(f"Target unreachable for case {c.endpoint.method} {c.endpoint.path}: {exc}")
                return None
            except Exception as exc:
                ctx.notes.append(f"Error running case {c.endpoint.method} {c.endpoint.path}: {exc}")
                return None

    # Run cases concurrently up to CASE_CONCURRENCY limit
    tasks = [_execute_single_case(c) for c in get_cases]
    for fut in asyncio.as_completed(tasks):
        res = await fut
        if res is not None:
            results.append(res)
        if budget_exhausted:
            break

    return results
