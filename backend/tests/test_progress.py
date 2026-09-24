"""Unit tests for progress tracking, monotonicity, stage ordering, and check events."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import pytest

from app.engine.checks import CHECKS
from app.engine.scanner import (
    ProgressEvent,
    ScanConfig,
    ScanStage,
    STAGE_WEIGHTS,
    _ProgressTracker,
)
from app.engine.identity import IdentityConfig


@pytest.mark.asyncio
async def test_progress_percent_never_decreases() -> None:
    """_ProgressTracker guarantees monotonically non-decreasing percent values."""
    emitted: list[dict] = []

    def on_progress(evt: dict) -> None:
        emitted.append(evt)

    tracker = _ProgressTracker(scan_id="test-monotonic", on_progress=on_progress)

    # Emit increasing then lower percentages
    await tracker.emit(ScanStage.LOADING_SPEC, 5, "Step 1")
    await tracker.emit(ScanStage.LOADING_SPEC, 8, "Step 2")
    await tracker.emit(ScanStage.MAPPING_SURFACE, 7, "Step 3 - lower percent attempted")
    await tracker.emit(ScanStage.AUTHENTICATING, 20, "Step 4")
    await tracker.emit(ScanStage.DISCOVERING, 15, "Step 5 - lower percent attempted")
    await tracker.emit(ScanStage.FINALIZING, 100, "Done")

    assert len(emitted) == 6
    percentages = [e["percent"] for e in emitted]
    # Verify every percentage is >= previous
    for i in range(1, len(percentages)):
        assert percentages[i] >= percentages[i - 1], f"Decreased from {percentages[i-1]} to {percentages[i]}"

    assert percentages == [5, 8, 8, 20, 20, 100]


@pytest.mark.asyncio
async def test_progress_stage_order_and_weights() -> None:
    """Stage sequence strictly adheres to STAGE_WEIGHTS definition."""
    expected_order = [
        ScanStage.QUEUED,
        ScanStage.LOADING_SPEC,
        ScanStage.MAPPING_SURFACE,
        ScanStage.AUTHENTICATING,
        ScanStage.DISCOVERING,
        ScanStage.PLANNING,
        ScanStage.RUNNING_CHECKS,
        ScanStage.REPRODUCING,
        ScanStage.FINALIZING,
    ]

    # Verify STAGE_WEIGHTS keys match expected_order exactly
    assert list(STAGE_WEIGHTS.keys()) == expected_order

    # Verify percentages in STAGE_WEIGHTS ranges are non-overlapping and contiguous
    prev_high = 0
    for stage in expected_order:
        low, high = STAGE_WEIGHTS[stage]
        assert low <= high
        assert low >= prev_high
        prev_high = high
    assert prev_high == 100


@pytest.mark.asyncio
async def test_progress_terminal_event_and_check_events() -> None:
    """Trackers emit exactly one terminal event and per-check progress events."""
    events: list[dict] = []

    def on_progress(evt: dict) -> None:
        events.append(evt)

    tracker = _ProgressTracker(scan_id="test-events", on_progress=on_progress)

    # Simulate scan flow
    await tracker.emit(ScanStage.QUEUED, 0, "Queued", status="queued")
    await tracker.emit(ScanStage.LOADING_SPEC, 5, "Loading spec", status="running")

    # Simulate check execution
    enabled_checks = ["bola", "bfla", "data_exposure"]
    for i, check_name in enumerate(enabled_checks, 1):
        pct = 38 + int((i / len(enabled_checks)) * (85 - 38))
        await tracker.emit(
            ScanStage.RUNNING_CHECKS,
            pct,
            f"Completed check {check_name}",
            status="running",
            check=check_name,
        )

    # Terminal event
    await tracker.emit(
        ScanStage.FINALIZING,
        100,
        "Scan complete",
        status="completed",
    )

    # 1. Check check-level events
    check_events = [e for e in events if e.get("check") is not None]
    assert len(check_events) == 3
    assert [e["check"] for e in check_events] == ["bola", "bfla", "data_exposure"]

    # 2. Exactly one terminal event
    terminal_events = [e for e in events if e["status"] in ("completed", "failed", "cancelled", "interrupted")]
    assert len(terminal_events) == 1
    assert terminal_events[0]["status"] == "completed"
    assert terminal_events[0]["percent"] == 100
    assert terminal_events[0]["stage"] == ScanStage.FINALIZING
