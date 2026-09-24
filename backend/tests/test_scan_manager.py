"""Unit tests for ScanManager orchestration, concurrency, cancellation, and error sanitization."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import pytest

from app.config import Settings
from app.engine.errors import ScanTimeoutError
from app.engine.identity import IdentityConfig
from app.engine.scanner import ScanConfig, ScanResult
from app.scan_manager import (
    ScanConcurrencyLimitError,
    ScanConflictError,
    ScanManager,
    ScanNotFoundError,
)
from app.store import JsonSnapshotStore


def _make_config(base_url: str = "http://127.0.0.1:9000", password: str = "SuperSecretPassword123!") -> ScanConfig:
    return ScanConfig(
        spec_inline={"openapi": "3.0.0", "paths": {}},
        base_url=base_url,
        identities=[
            IdentityConfig(
                name="tester",
                role="user",
                username="test_user",
                password=password,
                login_path="/auth/login",
            )
        ],
    )


def _make_settings(tmp_path: Path, max_concurrent: int = 2) -> Settings:
    return Settings(
        DATA_DIR=str(tmp_path),
        ALLOWED_HOSTS=["127.0.0.1", "localhost"],
        MAX_CONCURRENT_SCANS=max_concurrent,
    )


@pytest.mark.asyncio
async def test_scan_manager_submit_immediate(tmp_path: Path) -> None:
    """manager.submit returns immediately with a queued record while task runs in background."""
    store = JsonSnapshotStore(data_dir=str(tmp_path))
    settings = _make_settings(tmp_path)
    started_event = asyncio.Event()
    finish_event = asyncio.Event()

    async def fake_runner(cfg, on_progress, settings, scan_id):
        started_event.set()
        await finish_event.wait()
        return ScanResult(
            findings=[],
            surface=[],
            matrix={},
            matrix_summary={},
            plan_stats={},
            notes=[],
            summary={"total_findings": 0, "by_severity": {}},
            requests_sent=1,
            duration_seconds=0.1,
        )

    manager = ScanManager(store=store, settings=settings, runner=fake_runner)
    cfg = _make_config()

    # Submit should return immediately
    record = await manager.submit(cfg)
    assert record.id is not None
    assert record.status in ("queued", "running")

    # Confirm runner started
    await started_event.wait()
    finish_event.set()

    # Wait for completion
    task = manager._active_tasks.get(record.id)
    if task:
        await task

    updated = await store.get(record.id)
    assert updated is not None
    assert updated.status == "completed"


@pytest.mark.asyncio
async def test_scan_manager_duplicate_base_url_conflict(tmp_path: Path) -> None:
    """Submitting a scan for a base_url already active raises ScanConflictError (HTTP 409)."""
    store = JsonSnapshotStore(data_dir=str(tmp_path))
    settings = _make_settings(tmp_path)
    hang_event = asyncio.Event()

    async def fake_runner(cfg, on_progress, settings, scan_id):
        await hang_event.wait()
        return ScanResult()

    manager = ScanManager(store=store, settings=settings, runner=fake_runner)
    cfg = _make_config(base_url="http://127.0.0.1:9000")

    await manager.submit(cfg)

    # Second submit with exact same base_url
    with pytest.raises(ScanConflictError, match="A scan is already active"):
        await manager.submit(cfg)

    # Clean up
    hang_event.set()
    await manager.shutdown()


@pytest.mark.asyncio
async def test_scan_manager_concurrency_limit_429(tmp_path: Path) -> None:
    """Submitting beyond MAX_CONCURRENT_SCANS raises ScanConcurrencyLimitError (HTTP 429)."""
    store = JsonSnapshotStore(data_dir=str(tmp_path))
    settings = _make_settings(tmp_path, max_concurrent=2)
    hang_event = asyncio.Event()

    async def fake_runner(cfg, on_progress, settings, scan_id):
        await hang_event.wait()
        return ScanResult()

    manager = ScanManager(store=store, settings=settings, runner=fake_runner)

    # Submit 2 scans with different ports (both within allowed 127.0.0.1)
    await manager.submit(_make_config(base_url="http://127.0.0.1:9001"))
    await manager.submit(_make_config(base_url="http://127.0.0.1:9002"))

    # Third scan must be rejected with concurrency limit
    with pytest.raises(ScanConcurrencyLimitError, match="Maximum concurrent scans"):
        await manager.submit(_make_config(base_url="http://127.0.0.1:9003"))

    # Clean up
    hang_event.set()
    await manager.shutdown()


@pytest.mark.asyncio
async def test_scan_manager_cancel_and_shielded_cleanup(tmp_path: Path) -> None:
    """Cancelling a scan cancels the task and guarantees shielded cleanup executes."""
    store = JsonSnapshotStore(data_dir=str(tmp_path))
    settings = _make_settings(tmp_path)
    scan_started = asyncio.Event()
    cleanup_executed = False

    async def fake_cleanup():
        nonlocal cleanup_executed
        await asyncio.sleep(0.05)
        cleanup_executed = True

    async def fake_runner(cfg, on_progress, settings, scan_id):
        nonlocal cleanup_executed
        try:
            scan_started.set()
            while True:
                await asyncio.sleep(0.01)
        finally:
            await asyncio.shield(fake_cleanup())

    manager = ScanManager(store=store, settings=settings, runner=fake_runner)
    cfg = _make_config()

    rec = await manager.submit(cfg)
    await scan_started.wait()

    # Cancel scan
    cancelled = await manager.cancel(rec.id)
    assert cancelled is True

    # Assert shielded cleanup ran
    assert cleanup_executed is True

    # Verify store status is cancelled
    updated = await store.get(rec.id)
    assert updated is not None
    assert updated.status == "cancelled"

    # Cancelling an already finished scan returns False
    second_cancel = await manager.cancel(rec.id)
    assert second_cancel is False


@pytest.mark.asyncio
async def test_scan_manager_timeout_sanitized(tmp_path: Path) -> None:
    """ScanTimeoutError failure records sanitized message in store."""
    store = JsonSnapshotStore(data_dir=str(tmp_path))
    settings = _make_settings(tmp_path)

    async def fake_runner(cfg, on_progress, settings, scan_id):
        raise ScanTimeoutError("Scan timed out after 900 seconds.")

    manager = ScanManager(store=store, settings=settings, runner=fake_runner)
    rec = await manager.submit(_make_config())

    # Wait for runner task to process
    task = manager._active_tasks.get(rec.id)
    if task:
        await task

    updated = await store.get(rec.id)
    assert updated is not None
    assert updated.status == "failed"
    assert updated.error == "Scan timed out after 900 seconds."


@pytest.mark.asyncio
async def test_scan_manager_internal_error_sanitized(tmp_path: Path) -> None:
    """Non-SentinelError exceptions never expose tracebacks or internal messages to record."""
    store = JsonSnapshotStore(data_dir=str(tmp_path))
    settings = _make_settings(tmp_path)

    secret_trace_string = "CONFIDENTIAL_DB_PASSWORD_LEAK_SECRET_1234"

    async def fake_runner(cfg, on_progress, settings, scan_id):
        raise RuntimeError(secret_trace_string)

    manager = ScanManager(store=store, settings=settings, runner=fake_runner)
    rec = await manager.submit(_make_config())

    task = manager._active_tasks.get(rec.id)
    if task:
        await task

    updated = await store.get(rec.id)
    assert updated is not None
    assert updated.status == "failed"
    # Must NOT contain the internal message
    assert secret_trace_string not in (updated.error or "")
    # Must only contain the class name
    assert updated.error == "Internal scanner error (RuntimeError)"


@pytest.mark.asyncio
async def test_scan_manager_shutdown(tmp_path: Path) -> None:
    """manager.shutdown cancels active tasks and marks them interrupted."""
    store = JsonSnapshotStore(data_dir=str(tmp_path))
    settings = _make_settings(tmp_path)
    hang_event = asyncio.Event()

    async def fake_runner(cfg, on_progress, settings, scan_id):
        await hang_event.wait()
        return ScanResult()

    manager = ScanManager(store=store, settings=settings, runner=fake_runner)
    rec = await manager.submit(_make_config())

    await manager.shutdown()

    updated = await store.get(rec.id)
    assert updated is not None
    assert updated.status == "interrupted"
    assert updated.error == "Server restarted during scan"


@pytest.mark.asyncio
async def test_scan_manager_passwords_not_in_record(tmp_path: Path) -> None:
    """Password and credential objects are never stored on or accessible from the record."""
    store = JsonSnapshotStore(data_dir=str(tmp_path))
    settings = _make_settings(tmp_path)
    secret_pass = "P@sswordUltraSecret123!"

    async def fake_runner(cfg, on_progress, settings, scan_id):
        return ScanResult()

    manager = ScanManager(store=store, settings=settings, runner=fake_runner)
    cfg = _make_config(password=secret_pass)

    rec = await manager.submit(cfg)
    task = manager._active_tasks.get(rec.id)
    if task:
        await task

    # Check store record public view
    record = await store.get(rec.id)
    assert record is not None
    serialized = record.model_dump_json()

    assert secret_pass not in serialized
    assert "test_user" not in serialized
    assert record.config_public.get("identities") == [{"name": "tester", "role": "user"}]
