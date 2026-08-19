"""Periodic background work.

Retention needed something to run it, and the alternative — purging at startup,
after writes, and on reads — was three partial mechanisms standing in for one
missing thing. Each had a real gap: startup only helps if the process restarts,
post-write only runs while traffic arrives, and a read gate protects disclosure
without ever reclaiming disk. A server that captures content and then goes
quiet would hold it indefinitely.

This is deliberately small. It is an asyncio task loop tied to the application
lifespan, not a job queue: there is no durable state, no retries across
restarts, and no distribution. That matches what the work actually is —
idempotent housekeeping that is harmless to skip and harmless to repeat.

**Single process only.** The launcher starts one uvicorn worker. With several,
every worker would run its own copy; the jobs here are idempotent so that is
survivable rather than correct, and a real deployment story needs either leader
election or an external scheduler. Said here rather than discovered later.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from app.services.safe_logging import report

logger = logging.getLogger(__name__)

# Jobs run on a fixed interval rather than a wall-clock schedule. Retention is
# a promise about what gets disclosed — enforced on read — so the cadence here
# only governs how promptly the disk is reclaimed.
DEFAULT_INTERVAL_SECONDS = 300.0
# Concurrency is whatever asyncio's default executor allows. A semaphore was
# declared here and never acquired, which is a bound that exists only in the
# reader's head — worse than no bound, because it reads as enforced.


@dataclass
class Job:
    name: str
    interval_seconds: float
    run: Callable[[], Awaitable[None]]


class Scheduler:
    """Runs jobs periodically until the application shuts down."""

    def __init__(self) -> None:
        self._tasks: list[asyncio.Task[None]] = []
        self._stopping = asyncio.Event()
        # Threads outlive the tasks awaiting them. Cancelling a task that is
        # awaiting asyncio.to_thread detaches the worker rather than stopping
        # it, so a timeout that only cancels lets shutdown dispose the database
        # engine underneath a live session. This tracks the workers themselves.
        self._worker_count = 0
        self._worker_lock = threading.Lock()
        self._workers_idle = threading.Event()
        self._workers_idle.set()

    def _worker_started(self) -> None:
        with self._worker_lock:
            self._worker_count += 1
            self._workers_idle.clear()

    def _worker_finished(self) -> None:
        with self._worker_lock:
            self._worker_count -= 1
            if self._worker_count == 0:
                self._workers_idle.set()

    async def run_in_worker(self, fn: Callable[[], object]) -> object:
        """Run blocking work off the loop, tracked so shutdown can wait for it.

        The bookkeeping happens *inside* the thread. A ``finally`` around the
        await would run when the awaiting task is cancelled — which is exactly
        the moment the thread is still running — so the counter would drop to
        zero while a worker still held a session, and shutdown would stop
        waiting for the thing it is meant to wait for.
        """
        self._worker_started()

        def _tracked() -> object:
            try:
                return fn()
            finally:
                self._worker_finished()

        return await asyncio.to_thread(_tracked)

    def start(self, jobs: list[Job]) -> None:
        for job in jobs:
            self._tasks.append(asyncio.create_task(self._loop(job), name=f"scheduler:{job.name}"))
        logger.info("Scheduler started with %d job(s)", len(jobs))

    async def _loop(self, job: Job) -> None:
        # Run once immediately: after a restart there may already be expired
        # content, and waiting a full interval to reclaim it is a choice nobody
        # would make deliberately.
        while not self._stopping.is_set():
            try:
                await job.run()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # A failing job must never take down the server or stop its own
                # schedule; housekeeping that dies silently on first error is
                # worse than none, because it looks like it is running.
                report(logger, "warning", f"scheduled job {job.name} failed", exc)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=job.interval_seconds)
            except TimeoutError:
                continue

    async def stop(self, *, timeout_seconds: float = 30.0, worker_drain_seconds: float = 30.0) -> bool:
        """Signal the loops and wait for any in-flight run to finish.

        Deliberately does not cancel first. A retention run is awaiting
        ``asyncio.to_thread``, and cancelling that await does not stop the
        worker thread — it just detaches it, so ``gather`` returns and the
        caller disposes the database engine underneath a live session. That is
        the shutdown race this method previously claimed to prevent while
        causing it.

        Cancellation is the fallback if a job overruns the timeout, because a
        stuck job must not hold shutdown open forever.
        """
        self._stopping.set()
        if not self._tasks:
            logger.info("Scheduler stopped")
            return True
        done, pending = await asyncio.wait(self._tasks, timeout=timeout_seconds)
        for task in pending:
            logger.warning("scheduled job did not finish within %.0fs; cancelling", timeout_seconds)
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._tasks.clear()

        # Cancelling above only unblocked the loop; a detached worker may still
        # hold a session. Wait for the threads themselves, because the caller
        # disposes the engine as soon as this returns.
        if not self._workers_idle.is_set():
            # Its own bound, not the task timeout. That one limits how long a
            # loop may take to notice the stop signal; this one is about not
            # disposing the database engine underneath a thread that still owns
            # a session, which is the harm being prevented.
            logger.info("waiting for %d background worker(s) to finish", self._worker_count)
            await asyncio.to_thread(self._workers_idle.wait, worker_drain_seconds)
            if not self._workers_idle.is_set():
                # Reported, not just logged. Saying "disposal may race them" and
                # returning anyway left the caller to dispose regardless, which
                # is the outcome this is meant to prevent — the caller needs to
                # be able to decide.
                logger.error(
                    "background worker(s) still running after %.0fs; not safe to dispose the engine",
                    worker_drain_seconds,
                )
                return False
        logger.info("Scheduler stopped")
        return True


def retention_job(
    session_factory: Callable[[], object],
    *,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    scheduler: Scheduler | None = None,
) -> Job:
    """The content retention purge, as a scheduled job."""

    async def _run() -> None:
        from app.services.content_capture import purge_expired

        def _purge() -> int:
            with session_factory() as session:  # type: ignore[attr-defined]
                return purge_expired(session)

        # Off the event loop: this is synchronous database work, and blocking
        # the loop would stall every in-flight guard request. Through the
        # scheduler so shutdown can wait for the thread, not just the task.
        purged = await (scheduler.run_in_worker(_purge) if scheduler else asyncio.to_thread(_purge))
        if purged:
            logger.info("Retention purged %d expired content row(s)", purged)

    return Job(name="content-retention", interval_seconds=interval_seconds, run=_run)
