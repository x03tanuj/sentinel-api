"""AI analyst routes for SentinelAPI.

Routes:
  GET  /ai/status                          - Feature detection (always available)
  POST /scans/{id}/findings/{fid}/explain  - Explain a single finding
  POST /scans/{id}/explain-top             - Explain top-N findings
  POST /scans/{id}/ai-summary              - Executive summary

Security:
  - Respects the optional X-API-Key dependency (same as other scan routes).
  - LLM API key is never returned by any route.
  - The AI semaphore limits concurrent LLM calls.
  - Provider failures always return the template fallback (never 500 from LLM error).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel

from app.ai.analyst import AiAnalysis, analyze_finding, build_template_analysis, fingerprint, summarize_scan
from app.ai.payload import FRAMEWORK_HINTS
from app.ai.providers import (
    LLMProvider,
    _GEMINI_DEFAULT_MODEL,
    _GROQ_DEFAULT_MODEL,
    _OPENROUTER_DEFAULT_MODEL,
    get_provider,
)
from app.config import Settings, get_settings
from app.models import Finding
from app.routes.scans import get_store, verify_api_key
from app.store import ScanStore

logger = logging.getLogger(__name__)

router = APIRouter(tags=["AI Analyst"])

# Module-level semaphore; reset in tests by patching or using the lifespan
_ai_semaphore: asyncio.Semaphore | None = None


def get_semaphore(settings: Settings = Depends(get_settings)) -> asyncio.Semaphore:
    """Return (lazily create) the AI concurrency semaphore."""
    global _ai_semaphore
    if _ai_semaphore is None:
        _ai_semaphore = asyncio.Semaphore(settings.AI_CONCURRENCY)
    return _ai_semaphore


# ── Request / Response models ─────────────────────────────────────────────────

class AiStatusResponse(BaseModel):
    """Response for GET /ai/status."""

    enabled: bool
    provider: str | None = None
    model: str | None = None
    max_calls_per_scan: int


class ExplainRequest(BaseModel):
    """Request body for POST /scans/{id}/findings/{fid}/explain."""

    framework_hint: str = "generic"
    force_refresh: bool = False


class ExplainTopResponse(BaseModel):
    """Response for POST /scans/{id}/explain-top."""

    analyses: list[dict[str, Any]]
    skipped_count: int
    calls_used: int
    calls_remaining: int


class AiSummaryResponse(BaseModel):
    """Response for POST /scans/{id}/ai-summary."""

    text: str
    source: str
    model: str | None
    generated_at: str
    calls_used: int


# ── Helpers ───────────────────────────────────────────────────────────────────

def _provider_model_name(settings: Settings) -> str | None:
    """Return the effective model name for the current provider/settings."""
    if not settings.LLM_MODEL:
        provider_defaults = {
            "groq": _GROQ_DEFAULT_MODEL,
            "openrouter": _OPENROUTER_DEFAULT_MODEL,
            "gemini": _GEMINI_DEFAULT_MODEL,
        }
        return provider_defaults.get(settings.LLM_PROVIDER.lower())
    return settings.LLM_MODEL


def _is_ai_configured(settings: Settings) -> bool:
    return settings.AI_ENABLED and settings.LLM_API_KEY is not None


def _require_ai_configured(settings: Settings) -> None:
    if not _is_ai_configured(settings):
        raise HTTPException(
            status_code=503,
            detail="AI analyst is not configured on this server. Set AI_ENABLED=true and LLM_API_KEY.",
        )


async def _get_scan_record_finished(scan_id: str, store: ScanStore) -> Any:
    """Get a scan record asserting it is finished."""
    record = await store.get(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    if record.status not in ("completed", "failed", "cancelled", "interrupted"):
        raise HTTPException(
            status_code=409,
            detail=f"Scan '{scan_id}' is not finished (status: {record.status}). Wait for it to complete.",
        )
    return record


async def _check_call_cap(scan_id: str, store: ScanStore, settings: Settings) -> None:
    """Raise 429 if the scan's AI call budget is exhausted."""
    calls_used = await store.get_ai_calls_used(scan_id)
    if calls_used >= settings.AI_MAX_CALLS_PER_SCAN:
        raise HTTPException(
            status_code=429,
            detail=(
                f"AI call cap reached for scan '{scan_id}' "
                f"({calls_used}/{settings.AI_MAX_CALLS_PER_SCAN}). "
                "Use force_refresh=false to read cached results."
            ),
        )


def _validate_framework_hint(hint: str) -> None:
    if hint not in FRAMEWORK_HINTS:
        raise HTTPException(
            status_code=422,
            detail=f"framework_hint '{hint}' is not valid. Must be one of: {sorted(FRAMEWORK_HINTS)}.",
        )


def _finding_dict_to_model(fd: dict[str, Any]) -> Finding:
    """Reconstruct a Finding from its stored dict representation."""
    return Finding.model_validate(fd)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get(
    "/ai/status",
    response_model=AiStatusResponse,
    operation_id="get_ai_status",
    summary="AI feature detection",
    description="Returns whether the AI analyst is configured. Never returns the LLM API key. Always available.",
)
async def get_ai_status(
    _: Annotated[None, Depends(verify_api_key)],
    settings: Settings = Depends(get_settings),
) -> AiStatusResponse:
    """Feature detection endpoint for the UI."""
    configured = _is_ai_configured(settings)
    return AiStatusResponse(
        enabled=configured,
        provider=settings.LLM_PROVIDER if configured else None,
        model=_provider_model_name(settings) if configured else None,
        max_calls_per_scan=settings.AI_MAX_CALLS_PER_SCAN,
    )


@router.post(
    "/scans/{scan_id}/findings/{finding_id}/explain",
    response_model=AiAnalysis,
    operation_id="explain_finding",
    summary="Explain a finding with AI",
    description=(
        "Generate an AI explanation for a specific finding. "
        "Returns 503 when AI is not configured, 409 if scan is not finished, "
        "422 for invalid framework_hint, 429 when call cap is reached."
    ),
)
async def explain_finding(
    scan_id: str,
    finding_id: str,
    body: ExplainRequest = Body(default=ExplainRequest()),
    _: Annotated[None, Depends(verify_api_key)] = None,
    store: ScanStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
    semaphore: asyncio.Semaphore = Depends(get_semaphore),
) -> AiAnalysis:
    """Analyze a single finding and attach the result to the scan record."""
    _require_ai_configured(settings)
    _validate_framework_hint(body.framework_hint)

    record = await _get_scan_record_finished(scan_id, store)
    if not record.result:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' has no results.")

    # Find the finding in results
    finding_dict: dict[str, Any] | None = None
    for fd in record.result.findings:
        if fd.get("id") == finding_id:
            finding_dict = fd
            break

    if finding_dict is None:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found in scan '{scan_id}'.")

    finding = _finding_dict_to_model(finding_dict)
    provider = get_provider(settings)
    if provider is None:
        raise HTTPException(status_code=503, detail="AI provider could not be initialized.")

    model_name = _provider_model_name(settings) or "unknown"
    fp = fingerprint(finding, body.framework_hint, model_name)

    # Check cache (unless force_refresh)
    if not body.force_refresh:
        cached = await store.get_cached_analysis(scan_id, fp)
        if cached:
            logger.debug("AI cache hit for finding %s", finding_id)
            return AiAnalysis.model_validate(cached)

    # Check call cap before consuming a call
    await _check_call_cap(scan_id, store, settings)

    async with semaphore:
        analysis = await analyze_finding(finding, body.framework_hint, provider, settings)

    # Count as a consumed call only for LLM source (not template fallback)
    if analysis.source == "llm":
        await store.increment_ai_calls(scan_id)

    analysis_dict = analysis.model_dump(mode="json")
    await store.set_finding_analysis(scan_id, finding_id, fp, analysis_dict)
    return analysis


@router.post(
    "/scans/{scan_id}/explain-top",
    response_model=ExplainTopResponse,
    operation_id="explain_top_findings",
    summary="Explain the top-N findings",
    description=(
        "Explain the top-N findings by severity then confidence. "
        "Skips already-analyzed findings. Stops at the call cap and reports skipped."
    ),
)
async def explain_top(
    scan_id: str,
    n: int = Query(default=5, ge=1, le=10, description="Number of findings to explain"),
    framework_hint: str = Query(default="generic"),
    _: Annotated[None, Depends(verify_api_key)] = None,
    store: ScanStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
    semaphore: asyncio.Semaphore = Depends(get_semaphore),
) -> ExplainTopResponse:
    """Analyze the top-N findings, respecting the per-scan call cap."""
    _require_ai_configured(settings)
    _validate_framework_hint(framework_hint)

    record = await _get_scan_record_finished(scan_id, store)
    if not record.result:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' has no results.")

    _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        record.result.findings,
        key=lambda fd: (
            _SEV_ORDER.get(fd.get("severity", "INFO"), 99),
            -float(fd.get("confidence", 0.0)),
        ),
    )[:n]

    provider = get_provider(settings)
    if provider is None:
        raise HTTPException(status_code=503, detail="AI provider could not be initialized.")

    model_name = _provider_model_name(settings) or "unknown"
    analyses: list[dict[str, Any]] = []
    skipped = 0
    calls_used_before = await store.get_ai_calls_used(scan_id)

    for finding_dict in sorted_findings:
        finding = _finding_dict_to_model(finding_dict)
        fp = fingerprint(finding, framework_hint, model_name)

        # Check cache first
        cached = await store.get_cached_analysis(scan_id, fp)
        if cached and not finding_dict.get("ai_analysis") is None:
            analyses.append(cached)
            continue

        # Re-check cache with fp
        cached = await store.get_cached_analysis(scan_id, fp)
        if cached:
            analyses.append(cached)
            continue

        # Check cap
        current_calls = await store.get_ai_calls_used(scan_id)
        if current_calls >= settings.AI_MAX_CALLS_PER_SCAN:
            skipped += 1
            continue

        async with semaphore:
            analysis = await analyze_finding(finding, framework_hint, provider, settings)

        if analysis.source == "llm":
            await store.increment_ai_calls(scan_id)

        analysis_dict = analysis.model_dump(mode="json")
        await store.set_finding_analysis(scan_id, finding_dict["id"], fp, analysis_dict)
        analyses.append(analysis_dict)

    calls_used_after = await store.get_ai_calls_used(scan_id)
    calls_remaining = max(0, settings.AI_MAX_CALLS_PER_SCAN - calls_used_after)

    return ExplainTopResponse(
        analyses=analyses,
        skipped_count=skipped,
        calls_used=calls_used_after,
        calls_remaining=calls_remaining,
    )


@router.post(
    "/scans/{scan_id}/ai-summary",
    response_model=AiSummaryResponse,
    operation_id="generate_ai_summary",
    summary="Generate AI executive summary",
    description=(
        "Generate an AI executive summary for a completed scan. "
        "Returns 503 if unconfigured, 409 if scan is not finished, 429 if cap reached."
    ),
)
async def generate_ai_summary_route(
    scan_id: str,
    _: Annotated[None, Depends(verify_api_key)] = None,
    store: ScanStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
    semaphore: asyncio.Semaphore = Depends(get_semaphore),
) -> AiSummaryResponse:
    """Generate and attach an AI executive summary to the scan."""
    _require_ai_configured(settings)

    record = await _get_scan_record_finished(scan_id, store)
    if not record.result:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' has no results.")

    # Return existing summary if already generated
    if record.result.ai_summary:
        s = record.result.ai_summary
        return AiSummaryResponse(
            text=s.get("text", ""),
            source=s.get("source", "template"),
            model=s.get("model"),
            generated_at=s.get("generated_at", ""),
            calls_used=await store.get_ai_calls_used(scan_id),
        )

    await _check_call_cap(scan_id, store, settings)

    provider = get_provider(settings)
    if provider is None:
        raise HTTPException(status_code=503, detail="AI provider could not be initialized.")

    findings_models = [_finding_dict_to_model(fd) for fd in record.result.findings]

    async with semaphore:
        summary_dict = await summarize_scan(
            record.result.summary,
            findings_models,
            provider,
            settings,
        )

    if summary_dict.get("source") == "llm":
        await store.increment_ai_calls(scan_id)

    await store.set_ai_summary(scan_id, summary_dict)

    return AiSummaryResponse(
        text=summary_dict.get("text", ""),
        source=summary_dict.get("source", "template"),
        model=summary_dict.get("model"),
        generated_at=summary_dict.get("generated_at", ""),
        calls_used=await store.get_ai_calls_used(scan_id),
    )
