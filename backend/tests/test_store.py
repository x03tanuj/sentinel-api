"""Unit tests for ScanStore, JsonSnapshotStore, and the assert_no_secrets guard."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pytest

from app.engine.scanner import ScanResult
from app.store import (
    JsonSnapshotStore,
    ScanRecord,
    SecretLeakError,
    assert_no_secrets,
)


@pytest.fixture
def tmp_store(tmp_path: Path) -> JsonSnapshotStore:
    return JsonSnapshotStore(data_dir=str(tmp_path), max_stored=5)


@pytest.mark.asyncio
async def test_store_crud_and_ordering(tmp_store: JsonSnapshotStore) -> None:
    """Test create, get, and list ordering (newest first) with pagination."""
    r1 = await tmp_store.create({"base_url": "http://target1", "tag": "first"})
    await asyncio.sleep(0.01)
    r2 = await tmp_store.create({"base_url": "http://target2", "tag": "second"})
    await asyncio.sleep(0.01)
    r3 = await tmp_store.create({"base_url": "http://target3", "tag": "third"})

    # Get
    rec = await tmp_store.get(r2.id)
    assert rec is not None
    assert rec.id == r2.id
    assert rec.config_public.get("base_url") == "http://target2"

    # List order (newest first: r3, r2, r1)
    summaries = await tmp_store.list(limit=10, offset=0)
    assert len(summaries) == 3
    assert summaries[0]["id"] == r3.id
    assert summaries[1]["id"] == r2.id
    assert summaries[2]["id"] == r1.id

    # Pagination
    page1 = await tmp_store.list(limit=2, offset=0)
    assert len(page1) == 2
    assert page1[0]["id"] == r3.id
    assert page1[1]["id"] == r2.id

    page2 = await tmp_store.list(limit=2, offset=2)
    assert len(page2) == 1
    assert page2[0]["id"] == r1.id


@pytest.mark.asyncio
async def test_store_atomic_snapshot_roundtrip(tmp_path: Path) -> None:
    """Snapshot is written atomically to disk and cleanly reloaded by a new store instance."""
    store1 = JsonSnapshotStore(data_dir=str(tmp_path))
    rec = await store1.create({"base_url": "http://target-roundtrip"})
    await store1.update_status(rec.id, "running")

    result = ScanResult(
        findings=[],
        surface=[{"endpoint": "/orders", "score": 10}],
        matrix={"identities": ["u1"]},
        matrix_summary={"total_cells": 1},
        plan_stats={"total_generated": 5},
        notes=["all clear"],
        summary={"total_findings": 0, "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}},
        requests_sent=12,
        duration_seconds=1.5,
    )
    await store1.save_result(rec.id, result)
    await store1.flush()

    snapshot_file = tmp_path / "scans.json"
    assert snapshot_file.exists()

    # Check file mode (0o600 on platforms supporting it)
    mode = oct(snapshot_file.stat().st_mode & 0o777)
    assert mode == oct(0o600)

    # Reload in a new store instance
    store2 = JsonSnapshotStore(data_dir=str(tmp_path))
    reloaded = await store2.get(rec.id)
    assert reloaded is not None
    assert reloaded.status == "completed"
    assert reloaded.result is not None
    assert reloaded.result.requests_sent == 12
    assert reloaded.result.notes == ["all clear"]


@pytest.mark.asyncio
async def test_store_corrupt_snapshot_recovery(tmp_path: Path) -> None:
    """Corrupt snapshot file is renamed to scans.json.corrupt-<timestamp> and store starts empty."""
    snapshot_file = tmp_path / "scans.json"
    snapshot_file.write_text("{corrupt-invalid-json-data", encoding="utf-8")

    store = JsonSnapshotStore(data_dir=str(tmp_path))
    items = await store.list()
    assert items == []

    # Verify corrupt file was backed up and renamed
    corrupt_files = list(tmp_path.glob("scans.json.corrupt-*"))
    assert len(corrupt_files) == 1
    assert "{corrupt-invalid-json-data" in corrupt_files[0].read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_store_mark_interrupted_on_startup(tmp_path: Path) -> None:
    """Running or queued scans are marked interrupted when server starts up."""
    store1 = JsonSnapshotStore(data_dir=str(tmp_path))
    r_queued = await store1.create({"base_url": "http://queued"})
    r_running = await store1.create({"base_url": "http://running"})
    await store1.update_status(r_running.id, "running")
    await store1.flush()

    store2 = JsonSnapshotStore(data_dir=str(tmp_path))
    await store2.mark_interrupted_on_startup()

    q_updated = await store2.get(r_queued.id)
    r_updated = await store2.get(r_running.id)

    assert q_updated is not None and q_updated.status == "interrupted"
    assert q_updated.error == "Server restarted during scan"
    assert r_updated is not None and r_updated.status == "interrupted"
    assert r_updated.error == "Server restarted during scan"


@pytest.mark.asyncio
async def test_store_retention_policy(tmp_path: Path) -> None:
    """Retention keeps at most max_stored, evicts oldest finished scans, never running ones."""
    store = JsonSnapshotStore(data_dir=str(tmp_path), max_stored=3)

    # 1. Create a running scan (oldest created)
    r_running = await store.create({"base_url": "http://running-first"})
    await store.update_status(r_running.id, "running")

    # 2. Create 3 finished scans
    f1 = await store.create({"base_url": "http://fin-1"})
    await store.update_status(f1.id, "completed")

    f2 = await store.create({"base_url": "http://fin-2"})
    await store.update_status(f2.id, "completed")

    f3 = await store.create({"base_url": "http://fin-3"})
    await store.update_status(f3.id, "completed")

    # Store had 4 total. max_stored is 3.
    # r_running must NOT be evicted despite being oldest. f1 (oldest finished) should be evicted.
    records = [await store.get(r_running.id), await store.get(f1.id), await store.get(f2.id), await store.get(f3.id)]

    assert records[0] is not None  # r_running kept!
    assert records[1] is None      # f1 evicted!
    assert records[2] is not None  # f2 kept
    assert records[3] is not None  # f3 kept


@pytest.mark.asyncio
async def test_store_event_cap(tmp_store: JsonSnapshotStore) -> None:
    """Events list is capped at 300, dropping the oldest."""
    rec = await tmp_store.create({"base_url": "http://target-events"})

    for i in range(1, 351):
        event = {
            "seq": i,
            "scan_id": rec.id,
            "stage": "running_checks",
            "percent": min(100, i // 4),
            "message": f"Event {i}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await tmp_store.append_event(rec.id, event)

    updated = await tmp_store.get(rec.id)
    assert updated is not None
    assert len(updated.events) == 300
    # First event retained should be seq 51 (1 to 50 dropped)
    assert updated.events[0]["seq"] == 51
    assert updated.events[-1]["seq"] == 350


def test_assert_no_secrets_guard() -> None:
    """assert_no_secrets raises SecretLeakError on Bearer tokens, JWTs, and raw credentials."""
    # Clean payload
    clean = json.dumps({"status": "ok", "user": "alice", "roles": ["user"]})
    assert_no_secrets(clean)

    # Redacted values allowed
    redacted = json.dumps({"password": "********", "access_token": "[REDACTED]"})
    assert_no_secrets(redacted)

    # Bearer ey
    with pytest.raises(SecretLeakError, match="Bearer ey"):
        assert_no_secrets('{"auth": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fake"}')

    # Raw JWT-shaped string
    with pytest.raises(SecretLeakError, match="Raw JWT"):
        assert_no_secrets('{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}')

    # Non-redacted password
    with pytest.raises(SecretLeakError, match="Unredacted credential"):
        assert_no_secrets('{"username": "admin", "password": "supersecretpassword123"}')

    # Non-redacted access_token
    with pytest.raises(SecretLeakError, match="Unredacted credential"):
        assert_no_secrets('{"access_token": "abc123rawtokenvalue"}')


@pytest.mark.asyncio
async def test_store_concurrent_updates(tmp_store: JsonSnapshotStore) -> None:
    """Store handles concurrent async updates without state corruption."""
    rec = await tmp_store.create({"base_url": "http://concurrent-target"})

    async def _append(idx: int):
        await tmp_store.append_event(
            rec.id,
            {
                "seq": idx,
                "scan_id": rec.id,
                "stage": "running_checks",
                "percent": 50,
                "message": f"Concurrent event {idx}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    # Dispatch 50 concurrent appends
    await asyncio.gather(*[_append(i) for i in range(1, 51)])

    updated = await tmp_store.get(rec.id)
    assert updated is not None
    assert len(updated.events) == 50
