"""Scan manager for orchestrating scans, concurrency, events, and lifecycle."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timezone
import logging
from typing import Any

from app.config import Settings, assert_in_scope, get_settings
from app.engine.errors import (
    ScanTimeoutError,
    ScopeViolationError,
    SentinelError,
)
from app.engine.scanner import (
    ProgressEvent,
    ScanConfig,
    ScanResult,
    ScanStage,
    run_scan,
    safe_error_message,
)
from app.store import ScanRecord, ScanStore

logger = logging.getLogger(__name__)


class ScanConflictError(SentinelError):
    """Raised when another scan for the same base_url is already active."""


class ScanConcurrencyLimitError(SentinelError):
    """Raised when MAX_CONCURRENT_SCANS is reached."""


class ScanNotFoundError(SentinelError):
    """Raised when a requested scan ID does not exist."""


class ScanNotCancellableError(SentinelError):
    """Raised when trying to cancel an already completed/failed/cancelled scan."""


class ScanManager:
    """Manages scan submission, concurrency limits, execution tasks, and event streaming."""

    def __init__(
        self,
        store: ScanStore,
        settings: Settings | None = None,
        runner: Callable[..., Awaitable[ScanResult]] = run_scan,
    ) -> None:
        self.store = store
        self.settings = settings or get_settings()
        self.runner = runner
        self._active_tasks: dict[str, asyncio.Task[None]] = {}
        self._subscribers: dict[str, list[asyncio.Queue[dict[str, Any] | None]]] = {}
        self._lock = asyncio.Lock()

    async def submit(self, config: ScanConfig) -> ScanRecord:
        """Validate scope and concurrency, create scan record, and schedule execution.

        Args:
            config: Full scan configuration including credentials.

        Returns:
            Newly created ScanRecord (public view only).

        Raises:
            ScopeViolationError: If target or spec URL is not allowlisted.
            ScanConflictError: If a scan for base_url is already running.
            ScanConcurrencyLimitError: If MAX_CONCURRENT_SCANS limit is reached.
        """
        # 1. Validate scope immediately (raises ScopeViolationError -> HTTP 400)
        assert_in_scope(config.base_url, self.settings)
        if config.spec_url:
            assert_in_scope(config.spec_url, self.settings)

        async with self._lock:
            # 2. Check concurrency limit
            active_tasks = [t for t in self._active_tasks.values() if not t.done()]
            if len(active_tasks) >= self.settings.MAX_CONCURRENT_SCANS:
                raise ScanConcurrencyLimitError(
                    f"Maximum concurrent scans ({self.settings.MAX_CONCURRENT_SCANS}) reached. Try again later."
                )

            # 3. Check duplicate active scan for the same base_url
            for active_id, task in list(self._active_tasks.items()):
                if not task.done():
                    rec = await self.store.get(active_id)
                    if rec and rec.status in ("queued", "running"):
                        if rec.config_public.get("base_url") == config.base_url:
                            raise ScanConflictError(
                                f"A scan is already active for target: {config.base_url}"
                            )

            # 4. Create record in store with public_view only (NO CREDENTIALS)
            record = await self.store.create(config.public_view())
            scan_id = record.id

            # 5. Start background execution task
            self._subscribers[scan_id] = []
            task = asyncio.create_task(
                self._run_scan_task(scan_id, config),
                name=f"scan-task-{scan_id}",
            )
            self._active_tasks[scan_id] = task

            return record

    async def _run_scan_task(self, scan_id: str, config: ScanConfig | None) -> None:
        """Runner coroutine for executing the pipeline in the background."""
        try:
            await self.store.update_status(scan_id, "running")

            async def on_progress(event: dict[str, Any]) -> None:
                await self.store.append_event(scan_id, event)
                self._broadcast_event(scan_id, event)

            assert config is not None
            result = await self.runner(
                config,
                on_progress=on_progress,
                settings=self.settings,
                scan_id=scan_id,
            )
            await self.store.save_result(scan_id, result)

        except asyncio.CancelledError:
            logger.info("Scan %s received cancellation request", scan_id)
            rec = await self.store.get(scan_id)
            if rec and rec.status not in ("interrupted", "cancelled", "completed"):
                await self.store.update_status(scan_id, "cancelled", error="Scan was cancelled by user")
                term = ProgressEvent(
                    seq=(rec.progress.get("seq", 0) if rec.progress else 0) + 1,
                    scan_id=scan_id,
                    stage=ScanStage.FINALIZING,
                    status="cancelled",
                    percent=rec.progress.get("percent", 0) if rec.progress else 0,
                    message="Scan cancelled",
                    timestamp=datetime.now(timezone.utc),
                ).model_dump()
                term["timestamp"] = term["timestamp"].isoformat()
                await self.store.append_event(scan_id, term)
                self._broadcast_event(scan_id, term)
            raise

        except ScanTimeoutError as exc:
            err = safe_error_message(exc)
            logger.warning("Scan %s timed out: %s", scan_id, err)
            rec = await self.store.get(scan_id)
            await self.store.update_status(scan_id, "failed", error=err)
            term = ProgressEvent(
                seq=((rec.progress.get("seq", 0) if rec and rec.progress else 0) + 1),
                scan_id=scan_id,
                stage=ScanStage.FINALIZING,
                status="failed",
                percent=rec.progress.get("percent", 0) if rec and rec.progress else 0,
                message=err,
                timestamp=datetime.now(timezone.utc),
            ).model_dump()
            term["timestamp"] = term["timestamp"].isoformat()
            await self.store.append_event(scan_id, term)
            self._broadcast_event(scan_id, term)

        except Exception as exc:
            err = safe_error_message(exc)
            logger.exception("Scan %s encountered unhandled failure: %s", scan_id, err)
            rec = await self.store.get(scan_id)
            await self.store.update_status(scan_id, "failed", error=err)
            term = ProgressEvent(
                seq=((rec.progress.get("seq", 0) if rec and rec.progress else 0) + 1),
                scan_id=scan_id,
                stage=ScanStage.FINALIZING,
                status="failed",
                percent=rec.progress.get("percent", 0) if rec and rec.progress else 0,
                message=err,
                timestamp=datetime.now(timezone.utc),
            ).model_dump()
            term["timestamp"] = term["timestamp"].isoformat()
            await self.store.append_event(scan_id, term)
            self._broadcast_event(scan_id, term)

        finally:
            # Drop reference to config and all passwords from closure
            config = None
            self._active_tasks.pop(scan_id, None)
            self._close_subscribers(scan_id)

    async def cancel(self, scan_id: str) -> bool:
        """Cancel an active scan and wait boundedly for cleanup.

        Returns:
            True if cancelled, False if scan is already finished.

        Raises:
            ScanNotFoundError: If scan_id does not exist.
        """
        record = await self.store.get(scan_id)
        if record is None:
            raise ScanNotFoundError(f"Scan {scan_id} not found")

        if record.status not in ("queued", "running"):
            return False

        task = self._active_tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            try:
                # Wait boundedly for task to terminate (including shielded cleanup)
                async with asyncio.timeout(10.0):
                    await task
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass

        # Ensure status in store is updated
        updated = await self.store.get(scan_id)
        if updated and updated.status not in ("cancelled", "completed", "failed", "interrupted"):
            await self.store.update_status(scan_id, "cancelled", error="Scan was cancelled by user")
            term = ProgressEvent(
                seq=((updated.progress.get("seq", 0) if updated.progress else 0) + 1),
                scan_id=scan_id,
                stage=ScanStage.FINALIZING,
                status="cancelled",
                percent=updated.progress.get("percent", 0) if updated.progress else 0,
                message="Scan cancelled",
                timestamp=datetime.now(timezone.utc),
            ).model_dump()
            term["timestamp"] = term["timestamp"].isoformat()
            await self.store.append_event(scan_id, term)
            self._broadcast_event(scan_id, term)

        return True

    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        """Stream progress events for a scan, replaying past events first.

        Late subscribers to finished scans get all past events then stream terminates.
        """
        record = await self.store.get(scan_id)
        if record is None:
            raise ScanNotFoundError(f"Scan {scan_id} not found")

        # Create subscriber queue
        q: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        if scan_id not in self._subscribers:
            self._subscribers[scan_id] = []
        self._subscribers[scan_id].append(q)

        seen_seqs: set[int] = set()
        try:
            # 1. Replay past events from store
            for evt in record.events:
                seq = evt.get("seq", 0)
                seen_seqs.add(seq)
                yield evt
                if evt.get("status") in ("completed", "failed", "cancelled", "interrupted"):
                    return

            # If already finished, return
            if record.status in ("completed", "failed", "cancelled", "interrupted"):
                return

            # 2. Stream live events
            while True:
                item = await q.get()
                if item is None:
                    # Scan finished and subscriber queues closed
                    break

                seq = item.get("seq", 0)
                if seq in seen_seqs:
                    continue
                seen_seqs.add(seq)
                yield item

                if item.get("status") in ("completed", "failed", "cancelled", "interrupted"):
                    break
        finally:
            subs = self._subscribers.get(scan_id, [])
            if q in subs:
                subs.remove(q)

    def _broadcast_event(self, scan_id: str, event: dict[str, Any]) -> None:
        """Push an event to all active subscriber queues for a scan."""
        subs = self._subscribers.get(scan_id, [])
        for q in subs:
            q.put_nowait(event)

    def _close_subscribers(self, scan_id: str) -> None:
        """Signal EOF to all subscriber queues for a scan."""
        subs = self._subscribers.get(scan_id, [])
        for q in subs:
            q.put_nowait(None)
        self._subscribers.pop(scan_id, None)

    async def shutdown(self) -> None:
        """Gracefully cancel all active tasks and mark them interrupted."""
        active_ids = list(self._active_tasks.keys())
        for scan_id in active_ids:
            task = self._active_tasks.get(scan_id)
            if task and not task.done():
                task.cancel()

        tasks = [t for t in self._active_tasks.values() if not t.done()]
        if tasks:
            try:
                async with asyncio.timeout(10.0):
                    await asyncio.gather(*tasks, return_exceptions=True)
            except Exception:
                pass

        for scan_id in active_ids:
            rec = await self.store.get(scan_id)
            if rec and rec.status in ("queued", "running"):
                await self.store.update_status(scan_id, "interrupted", error="Server restarted during scan")

        self._active_tasks.clear()
