"""Periodic background work.

Retention needed something to run it, and the alternative — purging at startup,
after writes, and on reads — was three partial mechanisms standing in for one
missing thing. Each had a real gap: startup only helps if the process restarts,
post-write only runs while traffic arrives, and a read gate protects disclosure
without ever reclaiming disk. A server that captures content and then goes
quiet would hold it indefinitely.

This is deliberately small. It is an asyncio task loop tied to the application
lifespan, not a job queue: there is no durable state, no retries across
restarts, and no distribution. Every job here is idempotent and harmless to
repeat.

Harmless to *skip* is no longer true of all of them, and the difference is
worth stating. Skipping the content purge leaves expired content on disk that
the read gate still refuses to disclose. Skipping ``vault_retention_job``
would leave the plaintext-mapping rows on disk with nothing to reclaim them,
so startup does not let that happen quietly: if this scheduler does not
start, ``app/main.py`` withholds the keyring and reversible redaction is off,
which means no such row is written in the first place.

**Single process only**, and now enforced rather than assumed. The launcher
starts one uvicorn worker, and since the process lock landed a second worker
does not run its own copy of these jobs -- it fails to start, because the lock
is acquired per worker after the fork and the second acquisition is refused.
Before that, several workers each running every job was merely survivable on
the grounds that the jobs are idempotent.

That makes leader election unnecessary for this deployment shape rather than
merely deferred. A deployment that genuinely needs several processes against
one database needs a different storage story first; see
``app/services/process_lock.py``.
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

        Registration happens on the event loop *before* dispatch, and
        deregistration *inside* the thread. Both halves matter, and an earlier
        version of this docstring claimed both happened in the thread:

        - registering before dispatch leaves no window in which the work exists
          but is uncounted;
        - decrementing inside the thread is what stops a cancelled await
          dropping the count while the thread runs on. A ``finally`` around the
          await would fire at exactly the moment the worker is still running,
          so the counter would reach zero while a session was still held and
          shutdown would stop waiting for the thing it is meant to wait for.
        """
        self._worker_started()

        def _tracked() -> object:
            try:
                return fn()
            finally:
                self._worker_finished()

        return await asyncio.to_thread(_tracked)

    def drain_workers_sync(self, timeout_seconds: float = 30.0) -> bool:
        """Block until no worker threads remain. Returns whether they drained.

        Separate from :meth:`stop`, which drains as part of stopping and
        therefore runs too early: a task that had not reached
        :meth:`run_in_worker` when ``stop()`` completed registers a worker
        afterwards, and nothing would wait for it.
        """
        return self._workers_idle.wait(timeout_seconds)

    async def drain_workers(self, timeout_seconds: float = 30.0) -> bool:
        """The awaitable form. The wait itself runs off the loop."""
        return await asyncio.to_thread(self.drain_workers_sync, timeout_seconds)

    def start(self, jobs: list[Job]) -> None:
        """Create the job tasks.

        Anything after the first create_task() must be non-raising, or the
        caller concludes the scheduler never started while its tasks are
        already running — orphaned, never stopped, never drained, and the
        shutdown decision about disposing the engine made on the belief that
        no background work exists.
        """
        for job in jobs:
            self._tasks.append(asyncio.create_task(self._loop(job), name=f"scheduler:{job.name}"))
        report(logger, "info", f"Scheduler started with {len(jobs)} job(s)")

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
            report(logger, "info", "Scheduler stopped")
            return True
        done, pending = await asyncio.wait(self._tasks, timeout=timeout_seconds)
        for task in pending:
            report(logger, "warning", f"scheduled job did not finish within {timeout_seconds:.0f}s; cancelling")
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
            report(logger, "info", f"waiting for {self._worker_count} background worker(s) to finish")
            await asyncio.to_thread(self._workers_idle.wait, worker_drain_seconds)
            if not self._workers_idle.is_set():
                # Reported, not just logged. Saying "disposal may race them" and
                # returning anyway left the caller to dispose regardless, which
                # is the outcome this is meant to prevent — the caller needs to
                # be able to decide.
                report(
                    logger,
                    "error",
                    f"background worker(s) still running after {worker_drain_seconds:.0f}s; "
                    "not safe to dispose the engine",
                )
                return False
        report(logger, "info", "Scheduler stopped")
        return True


def export_abandon_job(
    session_factory: Callable[[], object],
    *,
    boot_id: str,
    interval_seconds: float = 300.0,
    scheduler: Scheduler | None = None,
) -> Job:
    """Terminate export attempts left pending by a process that is gone.

    **Never sends anything.** An attempt whose delivery is unknown must not be
    retried: that is how one disclosure becomes two.

    A pending row from the CURRENT boot is left alone however old. It is owned
    by a live coroutine that will settle it, or it is genuinely stuck -- and a
    stuck row surfaces through the derived pending-health signal and resolves on
    the next restart. Age has no role here, because no wall-clock bound on a
    synchronous SQLite operation exists to build one on.
    """

    async def _run() -> None:
        from app.services.content_export import abandon_foreign_pending

        def _sweep() -> int:
            with session_factory() as session:  # type: ignore[attr-defined]
                count = abandon_foreign_pending(session, boot_id=boot_id)
                session.commit()
                return count

        abandoned = await (scheduler.run_in_worker(_sweep) if scheduler else asyncio.to_thread(_sweep))
        if abandoned:
            report(
                logger,
                "warning",
                f"abandoned {abandoned} export attempt(s) left pending by a previous process; "
                "their delivery is unknown and nothing has been retried",
            )

    return Job(name="content-export-abandon", interval_seconds=interval_seconds, run=_run)


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
            report(logger, "info", f"Retention purged {purged} expired content row(s)")

    return Job(name="content-retention", interval_seconds=interval_seconds, run=_run)


def vault_retention_job(
    session_factory: Callable[[], object],
    *,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    scheduler: Scheduler | None = None,
) -> Job:
    """Delete vaults past their expiry, as a scheduled job.

    A vault holds the placeholder-to-original mapping that makes redaction
    reversible, which is to say it holds exactly the values the product exists
    to protect. Unlike captured content, this is not housekeeping that is
    merely nice to have: reversible redaction refuses to store a mapping at all
    unless this job is running, because a product that cannot promise to delete
    the plaintext mapping should not collect it. See ``app/main.py``.

    That is also why it is a separate job from ``retention_job`` rather than
    another query inside it. They answer to different callers -- one purges
    captured content and one purges vaults -- and folding them together would
    make a failure in either look like a failure in both.
    """

    async def _run() -> None:
        from app.vault_manager import purge_expired_vaults

        def _purge() -> int:
            with session_factory() as session:  # type: ignore[attr-defined]
                return purge_expired_vaults(session)

        # Off the event loop, and through the scheduler, for the same reasons
        # the content purge is: this is synchronous database work, and shutdown
        # has to be able to wait for the thread rather than only the task.
        purged = await (scheduler.run_in_worker(_purge) if scheduler else asyncio.to_thread(_purge))
        if purged:
            report(logger, "info", f"Retention purged {purged} expired vault row(s)")

    return Job(name="vault-retention", interval_seconds=interval_seconds, run=_run)
