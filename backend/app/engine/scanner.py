"""Unified scanning pipeline orchestrator for SentinelAPI.

Provides the single entry point (run_scan) shared across both the CLI and HTTP API,
orchestrating specification loading, attack surface mapping, identity authentication,
ownership discovery, matrix planning, check execution, empirical reproduction,
and result aggregation with progress streaming and shielded cleanup.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
import json
import logging
import re
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse
import uuid

from pydantic import BaseModel, Field, field_validator, model_validator

from app.config import Settings, assert_in_scope, get_settings
from app.engine.auth_matrix import build_matrix, summarize_matrix
from app.engine.checks import CHECKS
from app.engine.checks.base import run_checks
from app.engine.checks.bola import cleanup_created
from app.engine.context import ScanContext
from app.engine.discovery import discover_ownership
from app.engine.errors import ScanTimeoutError, ScopeViolationError, SentinelError
from app.engine.http_executor import Executor
from app.engine.identity import IdentityConfig, IdentityManager
from app.engine.reproduce import reproduce_top_findings
from app.engine.test_generator import generate_all
from app.models import Finding
from app.parser.describe import summarize
from app.parser.openapi_loader import load_spec, resolve_and_validate
from app.parser.risk_prioritizer import prioritize, score_endpoint
from app.parser.surface_mapper import build_attack_surface

logger = logging.getLogger(__name__)

IDENTITY_NAME_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class ScanStage(str, Enum):
    """Execution stages for a security scan."""

    QUEUED = "queued"
    LOADING_SPEC = "loading_spec"
    MAPPING_SURFACE = "mapping_surface"
    AUTHENTICATING = "authenticating"
    DISCOVERING = "discovering"
    PLANNING = "planning"
    RUNNING_CHECKS = "running_checks"
    REPRODUCING = "reproducing"
    FINALIZING = "finalizing"


STAGE_WEIGHTS: dict[ScanStage, tuple[int, int]] = {
    ScanStage.QUEUED: (0, 0),
    ScanStage.LOADING_SPEC: (0, 8),
    ScanStage.MAPPING_SURFACE: (8, 15),
    ScanStage.AUTHENTICATING: (15, 22),
    ScanStage.DISCOVERING: (22, 32),
    ScanStage.PLANNING: (32, 38),
    ScanStage.RUNNING_CHECKS: (38, 85),
    ScanStage.REPRODUCING: (85, 95),
    ScanStage.FINALIZING: (95, 100),
}


class ProgressEvent(BaseModel):
    """Monotonic progress update emitted during scan execution."""

    seq: int = Field(..., description="Monotonically increasing sequence number")
    scan_id: str = Field(..., description="Unique scan identifier")
    stage: ScanStage = Field(..., description="Current scan execution stage")
    status: str = Field(default="running", description="Status: queued, running, completed, failed, cancelled, interrupted")
    percent: int = Field(..., ge=0, le=100, description="Completion percentage (0-100, never decreasing)")
    message: str = Field(..., description="Short progress description without sensitive data")
    check: str | None = Field(default=None, description="Check name currently completing, if applicable")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of event emission")


class ScanConfig(BaseModel):
    """Complete specification required to execute a security scan."""

    spec_url: str | None = Field(default=None, description="URL to remote OpenAPI specification")
    spec_inline: dict[str, Any] | None = Field(default=None, description="Inline OpenAPI specification dictionary")
    base_url: str = Field(..., description="Base URL of target API")
    identities: list[IdentityConfig] = Field(..., min_length=1, description="List of test identity personas")
    enabled_checks: list[str] | None = Field(default=None, description="Optional subset of checks to execute")
    test_case_budget: int = Field(default=150, ge=1, description="Budget cap for generated test cases")
    max_requests: int = Field(default=1000, ge=1, description="Maximum total requests permitted for the scan")
    sample_bodies: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Sample request bodies for POST/PUT resource mutations",
    )

    @model_validator(mode="after")
    def validate_spec_source(self) -> ScanConfig:
        """Ensure exactly one of spec_url or spec_inline is provided and size is within bounds."""
        has_url = bool(self.spec_url and self.spec_url.strip())
        has_inline = self.spec_inline is not None

        if has_url == has_inline:
            raise ValueError("Exactly one of 'spec_url' or 'spec_inline' must be provided.")

        settings = get_settings()
        if has_inline:
            raw_bytes = json.dumps(self.spec_inline).encode("utf-8")
            if len(raw_bytes) > settings.MAX_SPEC_BYTES:
                raise ValueError(
                    f"Inline spec size ({len(raw_bytes)} bytes) exceeds MAX_SPEC_BYTES ({settings.MAX_SPEC_BYTES} bytes)."
                )

        # Validate identities
        if len(self.identities) > settings.MAX_IDENTITIES:
            raise ValueError(
                f"Number of identities ({len(self.identities)}) exceeds MAX_IDENTITIES ({settings.MAX_IDENTITIES})."
            )

        names_seen = set()
        for ident in self.identities:
            name = ident.name.strip()
            if not IDENTITY_NAME_REGEX.match(name):
                raise ValueError(
                    f"Identity name '{name}' is invalid. Names must match ^[A-Za-z0-9_-]{{1,32}}$."
                )
            if name.lower() == "anonymous":
                raise ValueError("Identity name 'anonymous' is reserved and cannot be configured.")
            if name in names_seen:
                raise ValueError(f"Duplicate identity name '{name}' detected. Identity names must be unique.")
            names_seen.add(name)

        # Validate enabled_checks
        if self.enabled_checks:
            for chk in self.enabled_checks:
                if chk not in CHECKS:
                    raise ValueError(
                        f"Unknown check name '{chk}'. Available checks: {list(CHECKS.keys())}"
                    )

        # Validate test_case_budget
        if self.test_case_budget > settings.MAX_TEST_CASE_BUDGET:
            raise ValueError(
                f"test_case_budget ({self.test_case_budget}) exceeds MAX_TEST_CASE_BUDGET ({settings.MAX_TEST_CASE_BUDGET})."
            )

        # Cap max_requests to MAX_REQUESTS_PER_SCAN
        if self.max_requests > settings.MAX_REQUESTS_PER_SCAN:
            self.max_requests = settings.MAX_REQUESTS_PER_SCAN

        # Validate sample_bodies sizes
        for res_name, body in self.sample_bodies.items():
            encoded = json.dumps(body).encode("utf-8")
            if len(encoded) > 20_480:
                raise ValueError(
                    f"Sample body for resource '{res_name}' exceeds maximum permitted size of 20 KB."
                )

        return self

    def public_view(self) -> dict[str, Any]:
        """Return the public, secret-free representation of the scan configuration.

        Never exposes usernames or passwords. This is the only representation stored or returned.
        """
        spec_source = "inline"
        if self.spec_url:
            parsed = urlparse(self.spec_url)
            spec_source = f"url:{parsed.netloc or parsed.path}"

        return {
            "base_url": self.base_url,
            "spec_source": spec_source,
            "identities": [{"name": i.name, "role": i.role} for i in self.identities],
            "enabled_checks": self.enabled_checks,
            "test_case_budget": self.test_case_budget,
            "max_requests": self.max_requests,
            "sample_resources": list(self.sample_bodies.keys()),
        }


class ScanResult(BaseModel):
    """Complete aggregated results and metadata of a completed scan."""

    findings: list[dict[str, Any]] = Field(default_factory=list, description="List of detected vulnerability findings")
    surface: list[dict[str, Any]] = Field(default_factory=list, description="Attack surface endpoints and risk weights")
    matrix: dict[str, Any] = Field(default_factory=dict, description="Authorization matrix heatmap data")
    matrix_summary: dict[str, Any] = Field(default_factory=dict, description="Summary counts of matrix cell outcomes")
    plan_stats: dict[str, Any] = Field(default_factory=dict, description="Test generation planning statistics")
    notes: list[str] = Field(default_factory=list, description="Execution and diagnostic telemetry notes")
    summary: dict[str, Any] = Field(default_factory=dict, description="High-level executive metrics summary")
    requests_sent: int = Field(default=0, description="Total HTTP requests dispatched")
    duration_seconds: float = Field(default=0.0, description="Total execution duration in seconds")


def safe_error_message(exc: Exception) -> str:
    """Format a clean, secret-free error message for end users."""
    if isinstance(exc, SentinelError):
        return str(exc)
    return f"Internal scanner error ({type(exc).__name__})"


class _ProgressTracker:
    """Tracks monotonic sequence and progress percentages."""

    def __init__(
        self,
        scan_id: str,
        on_progress: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None,
    ) -> None:
        self.scan_id = scan_id
        self.on_progress = on_progress
        self.seq = 0
        self.current_percent = 0

    async def emit(
        self,
        stage: ScanStage,
        percent: int,
        message: str,
        status: str = "running",
        check: str | None = None,
    ) -> None:
        self.seq += 1
        # Percent must never decrease
        self.current_percent = max(self.current_percent, min(100, max(0, percent)))
        event = ProgressEvent(
            seq=self.seq,
            scan_id=self.scan_id,
            stage=stage,
            status=status,
            percent=self.current_percent,
            message=message,
            check=check,
            timestamp=datetime.now(timezone.utc),
        )
        if self.on_progress:
            try:
                res = self.on_progress(event.model_dump())
                if asyncio.iscoroutine(res):
                    await res
            except Exception as exc:
                logger.debug("on_progress emission error: %s", exc)


async def run_scan(
    config: ScanConfig,
    on_progress: Callable[[dict[str, Any]], Awaitable[None] | None] | None = None,
    settings: Settings | None = None,
    scan_id: str | None = None,
) -> ScanResult:
    """Execute the full SentinelAPI security scanning pipeline.

    Unified single pipeline shared across CLI and API.

    Args:
        config: Verified scan configuration.
        on_progress: Optional callback invoked with ProgressEvent dictionary payloads.
        settings: Application settings; falls back to get_settings() if None.
        scan_id: Optional scan ID; generates a new UUID if not provided.

    Returns:
        Complete ScanResult containing findings, surface, matrix, and metrics.

    Raises:
        ScopeViolationError: If target or spec URL fails scope verification.
        ScanTimeoutError: If execution exceeds SCAN_TIMEOUT_SECONDS.
        SentinelError: If pipeline encounters an unrecoverable engine failure.
    """
    active_settings = settings or get_settings()
    active_scan_id = scan_id or str(uuid.uuid4())
    start_time = datetime.now(timezone.utc)
    tracker = _ProgressTracker(active_scan_id, on_progress)

    # 1. Scope Guard (Defense in Depth)
    assert_in_scope(config.base_url, active_settings)
    if config.spec_url:
        assert_in_scope(config.spec_url, active_settings)

    logger.info("Starting scan %s for %s", active_scan_id, config.base_url)
    await tracker.emit(ScanStage.QUEUED, 0, "Scan initialized and queued", status="running")

    ctx: ScanContext | None = None
    executor: Executor | None = None

    async def _pipeline() -> ScanResult:
        nonlocal ctx, executor

        # -------------------------------------------------------------
        # Stage 1: Loading Specification (0% - 8%)
        # -------------------------------------------------------------
        await tracker.emit(ScanStage.LOADING_SPEC, 2, "Loading and validating OpenAPI specification")
        if config.spec_url:
            raw_spec = await load_spec(config.spec_url, settings=active_settings)
        else:
            raw_spec = config.spec_inline or {}

        resolved_spec = resolve_and_validate(raw_spec)
        await tracker.emit(ScanStage.LOADING_SPEC, 8, "Specification validated and resolved")

        # -------------------------------------------------------------
        # Stage 2: Mapping Attack Surface (8% - 15%)
        # -------------------------------------------------------------
        await tracker.emit(ScanStage.MAPPING_SURFACE, 10, "Extracting endpoints and parameter schemas")
        raw_endpoints = build_attack_surface(resolved_spec)
        endpoints = prioritize(raw_endpoints)
        surface_summary = summarize(endpoints)
        await tracker.emit(
            ScanStage.MAPPING_SURFACE,
            15,
            f"Mapped attack surface: {len(endpoints)} endpoints ({surface_summary.get('auth_required', 0)} authenticated)",
        )

        # -------------------------------------------------------------
        # Stage 3: Authenticating Identities (15% - 22%)
        # -------------------------------------------------------------
        await tracker.emit(ScanStage.AUTHENTICATING, 16, f"Authenticating {len(config.identities)} test identities")
        # One executor per scan, bounded by config.max_requests
        scan_settings = active_settings.model_copy(update={"MAX_REQUESTS_PER_SCAN": config.max_requests})
        executor = Executor(settings=scan_settings)
        identity_mgr = IdentityManager(base_url=config.base_url, executor=executor)
        identities = await identity_mgr.login_all(config.identities)
        await tracker.emit(
            ScanStage.AUTHENTICATING,
            22,
            f"Authenticated {len(identities)} identities ({[i.name for i in identities]})",
        )

        # -------------------------------------------------------------
        # Stage 4: Discovering Ownership (22% - 32%)
        # -------------------------------------------------------------
        await tracker.emit(ScanStage.DISCOVERING, 24, "Discovering object ownership across identities")
        owned = await discover_ownership(
            endpoints=endpoints,
            identities=identities,
            executor=executor,
            base_url=config.base_url,
        )
        total_discovered = sum(len(objs) for res in owned.values() for objs in res.values())
        await tracker.emit(
            ScanStage.DISCOVERING,
            32,
            f"Ownership discovery complete: {total_discovered} owned objects cataloged",
        )

        # -------------------------------------------------------------
        # Stage 5: Planning Authorization Matrix & Test Cases (32% - 38%)
        # -------------------------------------------------------------
        await tracker.emit(ScanStage.PLANNING, 33, "Building authorization matrix and generating test plan")
        matrix_cells = build_matrix(owned, identities)
        gen_result = generate_all(
            endpoints=endpoints,
            identities=identities,
            owned=owned,
            matrix_cells=matrix_cells,
            budget=config.test_case_budget,
        )
        matrix_summary_data = summarize_matrix(matrix_cells)
        await tracker.emit(
            ScanStage.PLANNING,
            38,
            f"Test plan compiled: {len(gen_result.cases)} cases budgeted across {len(matrix_cells)} matrix cells",
        )

        # -------------------------------------------------------------
        # Stage 6: Executing Security Checks (38% - 85%)
        # -------------------------------------------------------------
        await tracker.emit(ScanStage.RUNNING_CHECKS, 39, "Beginning execution of security checks")
        ctx = ScanContext(
            base_url=config.base_url,
            endpoints=endpoints,
            identity_manager=identity_mgr,
            owned=owned,
            matrix_cells=matrix_cells,
            cases=gen_result.cases,
            executor=executor,
            settings=scan_settings,
            sample_bodies=config.sample_bodies,
        )

        # Progress tracking for running checks
        enabled_list = config.enabled_checks or list(CHECKS.keys())
        active_checks_count = max(1, len([c for c in enabled_list if c in CHECKS]))
        completed_checks = 0

        async def _on_check_completed(check_name: str) -> None:
            nonlocal completed_checks
            completed_checks += 1
            # Scale between 38% and 85%
            pct = 38 + int((completed_checks / active_checks_count) * (85 - 38))
            await tracker.emit(
                ScanStage.RUNNING_CHECKS,
                pct,
                f"Check completed: {check_name} ({completed_checks}/{active_checks_count})",
                check=check_name,
            )

        findings: list[Finding] = await run_checks(
            ctx,
            enabled=config.enabled_checks,
            on_check_done=_on_check_completed,
        )

        # -------------------------------------------------------------
        # Stage 7: Empirical Reproduction (85% - 95%)
        # -------------------------------------------------------------
        await tracker.emit(
            ScanStage.REPRODUCING,
            86,
            f"Beginning empirical reproduction for top findings (candidate count: {len(findings)})",
        )
        findings = await reproduce_top_findings(findings, ctx, top_n=8)
        await tracker.emit(ScanStage.REPRODUCING, 95, "Empirical reproduction complete")

        # -------------------------------------------------------------
        # Stage 8: Finalizing & Metric Aggregation (95% - 100%)
        # -------------------------------------------------------------
        await tracker.emit(ScanStage.FINALIZING, 96, "Aggregating findings and compiling executive summary")

        by_severity: dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        by_check: dict[str, int] = {}
        max_risk = 0
        reproduced_count = 0
        downgraded_count = 0

        for f in findings:
            sev_str = f.severity.value
            by_severity[sev_str] = by_severity.get(sev_str, 0) + 1
            by_check[f.check] = by_check.get(f.check, 0) + 1

            if f.evidence and f.evidence.response_diff:
                rd = f.evidence.response_diff
                r_score = rd.get("risk_score") or 0
                if r_score > max_risk:
                    max_risk = r_score

                repro = rd.get("reproduction")
                if repro and repro.get("reproduced", 0) > 0:
                    reproduced_count += 1
                if rd.get("downgraded"):
                    downgraded_count += 1

        top_findings_list: list[dict[str, Any]] = []
        for f in findings[:3]:
            top_findings_list.append({
                "title": f.title,
                "severity": f.severity.value,
                "endpoint": f.endpoint,
                "check": f.check,
            })

        duration = max(0.001, (datetime.now(timezone.utc) - start_time).total_seconds())

        summary_data: dict[str, Any] = {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_check": by_check,
            "endpoints_total": surface_summary.get("total", 0),
            "auth_required": surface_summary.get("auth_required", 0),
            "object_level": surface_summary.get("object_level", 0),
            "privileged": surface_summary.get("privileged", 0),
            "public": surface_summary.get("public", 0),
            "requests_sent": executor.requests_sent,
            "request_budget": config.max_requests,
            "cases_generated": gen_result.stats.get("total_generated", 0),
            "cases_kept": len(gen_result.cases),
            "reproduced_count": reproduced_count,
            "downgraded_count": downgraded_count,
            "max_risk_score": max_risk,
            "top_findings": top_findings_list,
        }

        surface_list = []
        for ep in endpoints:
            surface_list.append({
                "method": ep.method,
                "path": ep.path,
                "operation_id": ep.operation_id,
                "score": score_endpoint(ep),
                "resource": ep.resource,
                "requires_auth": ep.requires_auth,
                "is_object_level": ep.is_object_level,
                "is_privileged": ep.is_privileged,
                "path_params": ep.path_params,
                "query_params": ep.query_params,
                "tags": ep.tags,
            })
        matrix_dict = {
            "identities": [i.name for i in identities],
            "cells": [c.model_dump() for c in matrix_cells],
        }

        result = ScanResult(
            findings=[f.to_dict() for f in findings],
            surface=surface_list,
            matrix=matrix_dict,
            matrix_summary=matrix_summary_data,
            plan_stats=gen_result.stats,
            notes=list(ctx.notes),
            summary=summary_data,
            requests_sent=executor.requests_sent,
            duration_seconds=duration,
        )

        await tracker.emit(ScanStage.FINALIZING, 100, "Scan completed successfully", status="completed")
        return result

    try:
        async with asyncio.timeout(float(active_settings.SCAN_TIMEOUT_SECONDS)):
            return await _pipeline()
    except (asyncio.TimeoutError, TimeoutError) as exc:
        logger.warning("Scan %s timed out after %ds", active_scan_id, active_settings.SCAN_TIMEOUT_SECONDS)
        await tracker.emit(
            ScanStage.FINALIZING,
            tracker.current_percent,
            f"Scan timed out after {active_settings.SCAN_TIMEOUT_SECONDS}s",
            status="failed",
        )
        raise ScanTimeoutError(f"Scan timed out after {active_settings.SCAN_TIMEOUT_SECONDS} seconds.") from exc
    except Exception as exc:
        clean_msg = safe_error_message(exc)
        logger.exception("Scan %s failed: %s", active_scan_id, clean_msg)
        await tracker.emit(
            ScanStage.FINALIZING,
            tracker.current_percent,
            clean_msg,
            status="failed",
        )
        raise
    finally:
        # Guarantee shielded cleanup of test artifacts and HTTP connections
        if ctx is not None:
            try:
                await asyncio.shield(cleanup_created(ctx))
            except Exception as cleanup_exc:
                logger.debug("Shielded cleanup error: %s", cleanup_exc)
                if ctx is not None:
                    ctx.notes.append(f"cleanup_error: {type(cleanup_exc).__name__}")
        if executor is not None:
            try:
                await executor.aclose()
            except Exception:
                pass
