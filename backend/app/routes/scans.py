"""FastAPI routes for scan orchestration, inspection, events, and reports."""

from __future__ import annotations

import asyncio
from datetime import datetime
import hmac
import json
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from app.config import Settings, get_settings
from app.engine.checks import CHECKS
from app.engine.errors import ScopeViolationError
from app.engine.scanner import ScanConfig
from app.report import render_json, render_markdown
from app.scan_manager import (
    ScanConcurrencyLimitError,
    ScanConflictError,
    ScanManager,
    ScanNotFoundError,
)
from app.store import ScanRecord, ScanStore

router = APIRouter(prefix="/scans", tags=["scans"])

SEVERITY_WEIGHTS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


def _confidence_val(val: Any) -> float:
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        v = val.upper()
        if v == "HIGH":
            return 0.9
        if v == "MEDIUM":
            return 0.7
        if v == "LOW":
            return 0.4
        try:
            return float(val)
        except ValueError:
            return 0.0
    return 0.0


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def get_store(request: Request) -> ScanStore:
    """Retrieve ScanStore instance from application state."""
    return request.app.state.store


def get_scan_manager(request: Request) -> ScanManager:
    """Retrieve ScanManager instance from application state."""
    return request.app.state.scan_manager


def verify_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """Validate X-API-Key header if SENTINEL_API_KEY is configured."""
    settings: Settings = getattr(request.app.state, "settings", None) or get_settings()
    if settings.SENTINEL_API_KEY is not None and settings.SENTINEL_API_KEY.get_secret_value().strip():
        expected = settings.SENTINEL_API_KEY.get_secret_value()
        if not x_api_key or not hmac.compare_digest(x_api_key, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-API-Key header",
            )


# ---------------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------------


class ScanSubmitResponse(BaseModel):
    scan_id: str
    status: str
    status_url: str
    events_url: str


class ScanSummaryItem(BaseModel):
    id: str
    status: str
    created_at: datetime | str
    finished_at: datetime | str | None = None
    base_url: str
    total_findings: int
    by_severity: dict[str, int]


class ScanDetailResponse(BaseModel):
    id: str
    status: str
    created_at: datetime | str
    started_at: datetime | str | None = None
    finished_at: datetime | str | None = None
    progress: dict[str, Any]
    config_public: dict[str, Any]
    summary: dict[str, Any] | None = None
    error: str | None = None
    notes_count: int = 0


class FindingsListResponse(BaseModel):
    findings: list[dict[str, Any]]
    total: int


class SurfaceResponse(BaseModel):
    endpoints: list[dict[str, Any]]
    total: int


class MatrixResponse(BaseModel):
    identities: list[str]
    cells: list[dict[str, Any]]
    summary: dict[str, Any]


class NotesResponse(BaseModel):
    notes: list[str]
    total: int


class CancelResponse(BaseModel):
    scan_id: str
    cancelled: bool
    status: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanSubmitResponse,
    dependencies=[Depends(verify_api_key)],
    operation_id="submit_scan",
)
async def submit_scan(
    config: ScanConfig,
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanSubmitResponse:
    """Submit a new security scan job.

    Accepts target specification and identity credentials. Validates scope,
    schedules execution in the background, and returns tracking URLs.
    """
    try:
        record = await manager.submit(config)
    except ScopeViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target URL is out of authorized scope: {exc}",
        ) from exc
    except ScanConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ScanConcurrencyLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": "5"},
        ) from exc

    return ScanSubmitResponse(
        scan_id=record.id,
        status=record.status,
        status_url=f"/scans/{record.id}",
        events_url=f"/scans/{record.id}/events",
    )


@router.get(
    "",
    response_model=list[ScanSummaryItem],
    dependencies=[Depends(verify_api_key)],
    operation_id="list_scans",
)
async def list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    store: ScanStore = Depends(get_store),
) -> list[dict[str, Any]]:
    """List historical scan summaries ordered from newest to oldest."""
    return await store.list(limit=limit, offset=offset)


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    dependencies=[Depends(verify_api_key)],
    operation_id="get_scan",
)
async def get_scan(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> ScanDetailResponse:
    """Retrieve detailed scan execution metadata, public config, and summary metrics."""
    record = await store.get(scan_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    notes_cnt = len(record.result.notes) if (record.result and record.result.notes) else 0

    return ScanDetailResponse(
        id=record.id,
        status=record.status,
        created_at=record.created_at,
        started_at=record.started_at,
        finished_at=record.finished_at,
        progress=record.progress,
        config_public=record.config_public,
        summary=record.result.summary if record.result else None,
        error=record.error,
        notes_count=notes_cnt,
    )


@router.get(
    "/{scan_id}/findings",
    response_model=FindingsListResponse,
    dependencies=[Depends(verify_api_key)],
    operation_id="get_scan_findings",
)
async def get_scan_findings(
    scan_id: str,
    severity: str | None = Query(default=None),
    check: str | None = Query(default=None),
    min_confidence: float | None = Query(default=None),
    sort: str = Query(default="severity"),
    order: str = Query(default="desc"),
    store: ScanStore = Depends(get_store),
) -> FindingsListResponse:
    """Query and filter detected findings for a completed scan."""
    # Validate query parameters -> 422 if invalid
    if severity is not None and severity.upper() not in SEVERITY_WEIGHTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid severity filter. Allowed values: {list(SEVERITY_WEIGHTS.keys())}",
        )
    if check is not None and check not in CHECKS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown check name '{check}'. Allowed checks: {list(CHECKS.keys())}",
        )
    if min_confidence is not None and not (0.0 <= min_confidence <= 1.0):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="min_confidence must be between 0.0 and 1.0",
        )
    if sort not in ("severity", "confidence", "endpoint"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="sort must be one of: severity, confidence, endpoint",
        )
    if order.lower() not in ("asc", "desc"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="order must be one of: asc, desc",
        )

    record = await store.get(scan_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    if record.status in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {scan_id} is currently {record.status}. Findings are not yet available.",
        )

    if not record.result or not record.result.findings:
        return FindingsListResponse(findings=[], total=0)

    findings = list(record.result.findings)

    # 1. Apply Filters
    if severity:
        findings = [f for f in findings if f.get("severity", "").upper() == severity.upper()]
    if check:
        findings = [f for f in findings if f.get("check") == check]
    if min_confidence is not None:
        findings = [f for f in findings if _confidence_val(f.get("confidence")) >= min_confidence]

    # 2. Apply Sorting
    reverse = (order.lower() == "desc")
    if sort == "severity":
        findings.sort(key=lambda f: SEVERITY_WEIGHTS.get(f.get("severity", "INFO"), 1), reverse=reverse)
    elif sort == "confidence":
        findings.sort(key=lambda f: _confidence_val(f.get("confidence")), reverse=reverse)
    elif sort == "endpoint":
        findings.sort(key=lambda f: (f.get("endpoint", ""), f.get("method", "")), reverse=reverse)

    return FindingsListResponse(findings=findings, total=len(findings))


@router.get(
    "/{scan_id}/findings/{finding_id}",
    response_model=dict[str, Any],
    dependencies=[Depends(verify_api_key)],
    operation_id="get_scan_finding",
)
async def get_scan_finding(
    scan_id: str,
    finding_id: str,
    store: ScanStore = Depends(get_store),
) -> dict[str, Any]:
    """Retrieve full details of a specific finding by ID."""
    record = await store.get(scan_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    if record.status in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {scan_id} is currently {record.status}.",
        )

    if not record.result or not record.result.findings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found",
        )

    for finding in record.result.findings:
        if finding.get("id") == finding_id:
            return finding

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Finding {finding_id} not found",
    )


@router.get(
    "/{scan_id}/surface",
    response_model=SurfaceResponse,
    dependencies=[Depends(verify_api_key)],
    operation_id="get_scan_surface",
)
async def get_scan_surface(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> SurfaceResponse:
    """Retrieve mapped attack surface endpoints and risk prioritizations."""
    record = await store.get(scan_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    if record.status in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {scan_id} is currently {record.status}.",
        )

    surface = record.result.surface if record.result else []
    return SurfaceResponse(endpoints=surface, total=len(surface))


@router.get(
    "/{scan_id}/matrix",
    response_model=MatrixResponse,
    dependencies=[Depends(verify_api_key)],
    operation_id="get_scan_matrix",
)
async def get_scan_matrix(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> MatrixResponse:
    """Retrieve multi-identity authorization matrix and heatmap statistics."""
    record = await store.get(scan_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    if record.status in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {scan_id} is currently {record.status}.",
        )

    matrix = record.result.matrix if record.result else {}
    matrix_summary = record.result.matrix_summary if record.result else {}

    return MatrixResponse(
        identities=matrix.get("identities", []),
        cells=matrix.get("cells", []),
        summary=matrix_summary,
    )


@router.get(
    "/{scan_id}/notes",
    response_model=NotesResponse,
    dependencies=[Depends(verify_api_key)],
    operation_id="get_scan_notes",
)
async def get_scan_notes(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> NotesResponse:
    """Retrieve execution telemetry, skipped tests, and check notes."""
    record = await store.get(scan_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    if record.status in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {scan_id} is currently {record.status}.",
        )

    notes = record.result.notes if record.result else []
    return NotesResponse(notes=notes, total=len(notes))


@router.get(
    "/{scan_id}/events",
    dependencies=[Depends(verify_api_key)],
    operation_id="stream_scan_events",
)
async def stream_scan_events(
    scan_id: str,
    request: Request,
    manager: ScanManager = Depends(get_scan_manager),
    store: ScanStore = Depends(get_store),
) -> StreamingResponse:
    """Subscribe to real-time Server-Sent Events (SSE) for progress updates."""
    record = await store.get(scan_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    async def event_generator():
        gen = manager.subscribe(scan_id)
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    async with asyncio.timeout(15.0):
                        event = await anext(gen)
                        payload = json.dumps(event, default=str)
                        yield f"event: progress\ndata: {payload}\n\n"
                        if event.get("status") in ("completed", "failed", "cancelled", "interrupted"):
                            break
                except TimeoutError:
                    if await request.is_disconnected():
                        break
                    yield ": keep-alive\n\n"
                except StopAsyncIteration:
                    break
        finally:
            await gen.aclose()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post(
    "/{scan_id}/cancel",
    response_model=CancelResponse,
    dependencies=[Depends(verify_api_key)],
    operation_id="cancel_scan",
)
async def cancel_scan(
    scan_id: str,
    manager: ScanManager = Depends(get_scan_manager),
) -> CancelResponse:
    """Cancel an ongoing scan job gracefully, invoking shielded resource cleanup."""
    try:
        cancelled = await manager.cancel(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    if not cancelled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {scan_id} is already finished or cannot be cancelled.",
        )

    return CancelResponse(scan_id=scan_id, cancelled=True, status="cancelled")


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(verify_api_key)],
    operation_id="delete_scan",
)
async def delete_scan(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> Response:
    """Delete a scan record and its artifacts from storage."""
    record = await store.get(scan_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    if record.status in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {scan_id} is currently {record.status} and cannot be deleted.",
        )

    deleted = await store.delete(scan_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{scan_id}/report.json",
    dependencies=[Depends(verify_api_key)],
    operation_id="get_scan_report_json",
)
async def get_scan_report_json(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> Response:
    """Download full scan report as a JSON file attachment."""
    record = await store.get(scan_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    if record.status in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {scan_id} is currently {record.status}.",
        )

    content = render_json(record)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="sentinel_scan_{scan_id}.json"'},
    )


@router.get(
    "/{scan_id}/report.md",
    dependencies=[Depends(verify_api_key)],
    operation_id="get_scan_report_md",
)
async def get_scan_report_md(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> Response:
    """Download executive scan report as a Markdown file attachment."""
    record = await store.get(scan_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )

    if record.status in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {scan_id} is currently {record.status}.",
        )

    content = render_markdown(record)
    return Response(
        content=content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="sentinel_scan_{scan_id}.md"'},
    )
