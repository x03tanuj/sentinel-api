"""In-memory scan store with atomic JSON snapshotting and secret leak prevention.

Maintains scan state, progress events, and results in memory while persisting periodic
atomic snapshots to {DATA_DIR}/scans.json with strict secret leakage assertions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
from typing import Any
import uuid

from pydantic import BaseModel, Field

from app.config import get_settings
from app.engine.scanner import ScanResult

logger = logging.getLogger(__name__)

# Regular expressions for detecting raw credentials and sensitive tokens
BEARER_EY_REGEX = re.compile(r"Bearer\s+ey", re.IGNORECASE)
JWT_STRUCTURE_REGEX = re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
UNREDACTED_PASSWORD_REGEX = re.compile(
    r'"(?:password|access_token)"\s*:\s*"([^"]+)"',
    re.IGNORECASE,
)


class SecretLeakError(ValueError):
    """Raised when an unredacted credential or token is detected in serialized output."""


def assert_no_secrets(payload: str) -> None:
    """Validate that a serialized snapshot payload contains zero credentials or tokens.

    Raises:
        SecretLeakError: If a Bearer JWT, raw JWT structure, or unredacted password/token is detected.
    """
    if BEARER_EY_REGEX.search(payload):
        raise SecretLeakError("Secret leak detected: 'Bearer ey' token structure present in payload.")

    if JWT_STRUCTURE_REGEX.search(payload):
        raise SecretLeakError("Secret leak detected: Raw JWT token structure present in payload.")

    for match in UNREDACTED_PASSWORD_REGEX.finditer(payload):
        val = match.group(1).strip()
        # Allow properly redacted or masked values
        is_redacted = (
            val == "***REDACTED***"
            or val == "[REDACTED]"
            or val.startswith("***")
            or "****" in val
        )
        if not is_redacted:
            raise SecretLeakError(
                f"Secret leak detected: Unredacted credential found for key '{match.group(0)[:25]}...'."
            )


class ScanRecord(BaseModel):
    """Encapsulates the complete lifecycle state and results of a scan."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: str = Field(default="queued")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    config_public: dict[str, Any] = Field(default_factory=dict)
    progress: dict[str, Any] = Field(default_factory=dict)
    events: list[dict[str, Any]] = Field(default_factory=list)
    result: ScanResult | None = None
    error: str | None = None
    ai_cache: dict[str, Any] = Field(default_factory=dict, description="fingerprint → AiAnalysis dict; persisted in snapshot")
    ai_calls_used: int = Field(default=0, description="LLM API calls consumed for this scan")


class ScanStore(ABC):
    """Abstract interface for scan record storage and retrieval."""

    @abstractmethod
    async def create(self, config_public: dict[str, Any], scan_id: str | None = None) -> ScanRecord:
        """Create a new scan record."""
        pass

    @abstractmethod
    async def get(self, scan_id: str) -> ScanRecord | None:
        """Retrieve a scan record by ID."""
        pass

    @abstractmethod
    async def list(self, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
        """List lightweight scan summaries, newest first."""
        pass

    @abstractmethod
    async def update_status(
        self,
        scan_id: str,
        status: str,
        error: str | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> ScanRecord | None:
        """Update scan status and error/timestamp metadata."""
        pass

    @abstractmethod
    async def append_event(self, scan_id: str, event: dict[str, Any]) -> None:
        """Append a progress event and update latest progress pointer."""
        pass

    @abstractmethod
    async def save_result(self, scan_id: str, result: ScanResult) -> ScanRecord | None:
        """Save finalized scan result and mark scan completed."""
        pass

    @abstractmethod
    async def delete(self, scan_id: str) -> bool:
        """Delete a scan record."""
        pass

    @abstractmethod
    async def mark_interrupted_on_startup(self) -> int:
        """Mark any lingering queued or running scans as interrupted."""
        pass

    @abstractmethod
    async def set_finding_analysis(
        self, scan_id: str, finding_id: str, fp: str, analysis: dict[str, Any]
    ) -> bool:
        """Attach an AI analysis to a finding and update the AI cache."""
        pass

    @abstractmethod
    async def set_ai_summary(self, scan_id: str, summary: dict[str, Any]) -> bool:
        """Attach the AI executive summary to a scan's result."""
        pass

    @abstractmethod
    async def increment_ai_calls(self, scan_id: str, count: int = 1) -> int:
        """Increment ai_calls_used counter and return the new total."""
        pass

    @abstractmethod
    async def get_ai_calls_used(self, scan_id: str) -> int:
        """Return current ai_calls_used for the scan."""
        pass


class JsonSnapshotStore(ScanStore):
    """In-memory store backed by atomic JSON snapshots to disk.

    Thread-safe and async-safe via a dedicated asyncio.Lock.
    """

    def __init__(
        self,
        data_dir: Path | str | None = None,
        max_stored_scans: int | None = None,
        max_stored: int | None = None,
    ) -> None:
        settings = get_settings()
        self.data_dir = Path(data_dir or settings.DATA_DIR)
        self.max_stored_scans = max_stored or max_stored_scans or settings.MAX_STORED_SCANS
        self.snapshot_file = self.data_dir / "scans.json"
        self._records: dict[str, ScanRecord] = {}
        self._lock = asyncio.Lock()
        self._debounce_task: asyncio.Task[None] | None = None

        self._load_snapshot_sync()

    async def flush(self) -> None:
        """Explicitly flush state to disk snapshot."""
        async with self._lock:
            await self._write_snapshot_locked()

    def _load_snapshot_sync(self) -> None:
        """Load initial records from disk snapshot on startup."""
        if not self.snapshot_file.exists():
            return

        try:
            with open(self.snapshot_file, "r", encoding="utf-8") as fp:
                data = json.load(fp)

            if isinstance(data, list):
                for item in data:
                    try:
                        record = ScanRecord.model_validate(item)
                        self._records[record.id] = record
                    except Exception as parse_exc:
                        logger.warning("Skipping malformed scan record: %s", parse_exc)
        except Exception as exc:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            corrupt_path = self.data_dir / f"scans.json.corrupt-{timestamp}"
            logger.warning(
                "Failed to load snapshot from %s: %s. Renaming to %s and starting empty.",
                self.snapshot_file,
                exc,
                corrupt_path,
            )
            try:
                os.replace(self.snapshot_file, corrupt_path)
            except Exception as rename_exc:
                logger.error("Failed to rename corrupt snapshot file: %s", rename_exc)
            self._records.clear()

    async def mark_interrupted_on_startup(self) -> int:
        """Turn any active (queued or running) scans from prior server sessions into 'interrupted'."""
        async with self._lock:
            interrupted_count = 0
            now = datetime.now(timezone.utc)
            for record in self._records.values():
                if record.status in ("queued", "running"):
                    record.status = "interrupted"
                    record.error = "Server restarted during scan"
                    record.finished_at = now
                    interrupted_count += 1

            if interrupted_count > 0:
                await self._write_snapshot_locked()

            return interrupted_count

    async def _write_snapshot_locked(self) -> None:
        """Write current records to snapshot file atomically with secret verification."""
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(
                [r.model_dump(mode="json") for r in self._records.values()],
                indent=2,
            )

            # Strict security guard against persisting secrets
            assert_no_secrets(payload)

            temp_file = self.data_dir / f"scans.json.tmp.{uuid.uuid4()}"
            with open(temp_file, "w", encoding="utf-8") as fp:
                fp.write(payload)

            # Restrict file permissions where supported
            try:
                os.chmod(temp_file, 0o600)
            except Exception:
                pass

            os.replace(temp_file, self.snapshot_file)
        except ValueError as sec_err:
            logger.error("Snapshot write aborted due to secret detection guard: %s", sec_err)
        except Exception as exc:
            logger.exception("Failed to write snapshot to %s: %s", self.snapshot_file, exc)

    def _enforce_retention_locked(self) -> None:
        """Evict oldest finished scans if record count exceeds max_stored_scans."""
        if len(self._records) <= self.max_stored_scans:
            return

        # Sort finished scans by created_at (oldest first)
        finished_scans = [
            r for r in self._records.values()
            if r.status in ("completed", "failed", "cancelled", "interrupted")
        ]
        finished_scans.sort(key=lambda r: r.created_at)

        excess = len(self._records) - self.max_stored_scans
        for record in finished_scans[:excess]:
            del self._records[record.id]

    async def create(self, config_public: dict[str, Any], scan_id: str | None = None) -> ScanRecord:
        """Create a new scan record."""
        async with self._lock:
            active_id = scan_id or str(uuid.uuid4())
            record = ScanRecord(
                id=active_id,
                status="queued",
                created_at=datetime.now(timezone.utc),
                config_public=config_public,
                progress={
                    "seq": 0,
                    "scan_id": active_id,
                    "stage": "queued",
                    "status": "queued",
                    "percent": 0,
                    "message": "Scan queued",
                },
            )
            self._records[active_id] = record
            self._enforce_retention_locked()
            await self._write_snapshot_locked()
            return record

    async def get(self, scan_id: str) -> ScanRecord | None:
        """Retrieve a scan record by ID."""
        async with self._lock:
            return self._records.get(scan_id)

    async def list(self, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
        """List lightweight summaries of scans, newest first."""
        async with self._lock:
            # Sort newest first by created_at
            sorted_records = sorted(
                self._records.values(),
                key=lambda r: r.created_at,
                reverse=True,
            )
            page = sorted_records[offset : offset + limit]

            summaries: list[dict[str, Any]] = []
            for r in page:
                total_f = 0
                by_sev: dict[str, int] = {}
                if r.result and r.result.summary:
                    total_f = r.result.summary.get("total_findings", 0)
                    by_sev = r.result.summary.get("by_severity", {})

                summaries.append({
                    "id": r.id,
                    "status": r.status,
                    "created_at": r.created_at.isoformat(),
                    "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                    "base_url": r.config_public.get("base_url", ""),
                    "total_findings": total_f,
                    "by_severity": by_sev,
                })
            return summaries

    async def update_status(
        self,
        scan_id: str,
        status: str,
        error: str | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> ScanRecord | None:
        """Update scan status and snapshot state to disk."""
        async with self._lock:
            record = self._records.get(scan_id)
            if not record:
                return None

            record.status = status
            if error is not None:
                record.error = error
            if started_at is not None:
                record.started_at = started_at
            if finished_at is not None:
                record.finished_at = finished_at

            await self._write_snapshot_locked()
            return record

    async def append_event(self, scan_id: str, event: dict[str, Any]) -> None:
        """Append a progress event, cap events at 300, and update latest progress pointer."""
        async with self._lock:
            record = self._records.get(scan_id)
            if not record:
                return

            record.progress = event
            record.events.append(event)
            if len(record.events) > 300:
                record.events = record.events[-300:]

            # Snapshot on terminal event statuses
            if event.get("status") in ("completed", "failed", "cancelled", "interrupted"):
                await self._write_snapshot_locked()

    async def save_result(self, scan_id: str, result: ScanResult) -> ScanRecord | None:
        """Save scan result, mark completed, and trigger atomic snapshot."""
        async with self._lock:
            record = self._records.get(scan_id)
            if not record:
                return None

            record.result = result
            record.status = "completed"
            record.finished_at = datetime.now(timezone.utc)
            self._enforce_retention_locked()
            await self._write_snapshot_locked()
            return record

    async def delete(self, scan_id: str) -> bool:
        """Delete a scan record from memory and disk."""
        async with self._lock:
            if scan_id in self._records:
                del self._records[scan_id]
                await self._write_snapshot_locked()
                return True
            return False

    async def set_finding_analysis(
        self, scan_id: str, finding_id: str, fp: str, analysis: dict[str, Any]
    ) -> bool:
        """Attach an AI analysis dict to a finding by ID and cache by fingerprint.

        The analysis dict must already be safe (caller must pass sanitized data).
        """
        async with self._lock:
            record = self._records.get(scan_id)
            if not record or not record.result:
                return False

            updated = False
            for finding_dict in record.result.findings:
                if finding_dict.get("id") == finding_id:
                    finding_dict["ai_analysis"] = analysis
                    updated = True
                    break

            if updated:
                # Cache by fingerprint
                record.ai_cache[fp] = analysis
                await self._write_snapshot_locked()
            return updated

    async def set_ai_summary(self, scan_id: str, summary: dict[str, Any]) -> bool:
        """Attach the AI executive summary to a scan result."""
        async with self._lock:
            record = self._records.get(scan_id)
            if not record or not record.result:
                return False
            record.result.ai_summary = summary
            await self._write_snapshot_locked()
            return True

    async def increment_ai_calls(self, scan_id: str, count: int = 1) -> int:
        """Increment the AI call counter for this scan and return the new total."""
        async with self._lock:
            record = self._records.get(scan_id)
            if not record:
                return 0
            record.ai_calls_used += count
            # Mirror into result if it exists
            if record.result:
                record.result.ai_calls_used = record.ai_calls_used
            return record.ai_calls_used

    async def get_ai_calls_used(self, scan_id: str) -> int:
        """Return the current AI call count for this scan."""
        async with self._lock:
            record = self._records.get(scan_id)
            if not record:
                return 0
            return record.ai_calls_used

    async def get_cached_analysis(self, scan_id: str, fp: str) -> dict[str, Any] | None:
        """Return a cached analysis dict for the given fingerprint, or None."""
        async with self._lock:
            record = self._records.get(scan_id)
            if not record:
                return None
            return record.ai_cache.get(fp)
