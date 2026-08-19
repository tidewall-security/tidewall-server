"""The periodic job runner (P0-6, step 5).

Retention previously ran at startup, after writes, and as a read gate — three
partial mechanisms standing in for one missing thing. Each had a real gap:
startup only helps if the process restarts, post-write only runs while traffic
arrives, and the read gate protects disclosure without ever reclaiming disk. A
server that captured content and then went quiet would hold it indefinitely.
"""

from __future__ import annotations

import asyncio

from app.services.scheduler import Job, Scheduler


def test_a_job_runs_immediately_rather_than_after_one_interval():
    """After a restart there may already be expired content, and waiting a full
    interval to reclaim it is a choice nobody would make deliberately."""
    runs: list[int] = []

    async def _run() -> None:
        runs.append(1)

    async def _main() -> None:
        scheduler = Scheduler()
        scheduler.start([Job(name="t", interval_seconds=3600, run=_run)])
        await asyncio.sleep(0.05)
        await scheduler.stop()

    asyncio.run(_main())
    assert runs, "the job did not run before its first interval elapsed"


def test_a_job_repeats_on_its_interval():
    runs: list[int] = []

    async def _run() -> None:
        runs.append(1)

    async def _main() -> None:
        scheduler = Scheduler()
        scheduler.start([Job(name="t", interval_seconds=0.01, run=_run)])
        await asyncio.sleep(0.08)
        await scheduler.stop()

    asyncio.run(_main())
    assert len(runs) > 1, f"job ran {len(runs)} time(s); it should repeat"


def test_a_failing_job_keeps_its_schedule():
    """Housekeeping that dies silently on first error is worse than none,
    because it looks like it is running."""
    attempts: list[int] = []

    async def _run() -> None:
        attempts.append(1)
        raise RuntimeError("boom")

    async def _main() -> None:
        scheduler = Scheduler()
        scheduler.start([Job(name="t", interval_seconds=0.01, run=_run)])
        await asyncio.sleep(0.08)
        await scheduler.stop()

    asyncio.run(_main())
    assert len(attempts) > 1, "the job stopped after its first failure"


def test_a_failing_job_does_not_propagate():
    """It must not take down the server."""

    async def _run() -> None:
        raise RuntimeError("boom")

    async def _main() -> None:
        scheduler = Scheduler()
        scheduler.start([Job(name="t", interval_seconds=0.01, run=_run)])
        await asyncio.sleep(0.05)
        await scheduler.stop()

    asyncio.run(_main())  # must not raise


def test_stop_ends_the_loops():
    runs: list[int] = []

    async def _run() -> None:
        runs.append(1)

    async def _main() -> int:
        scheduler = Scheduler()
        scheduler.start([Job(name="t", interval_seconds=0.01, run=_run)])
        await asyncio.sleep(0.05)
        await scheduler.stop()
        settled = len(runs)
        await asyncio.sleep(0.05)
        return settled

    settled = asyncio.run(_main())
    assert len(runs) == settled, "the job kept running after stop()"


def test_the_retention_job_purges_expired_content():
    """End to end through the real job, not the helper it calls."""
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.db.models import Base, Interaction, InteractionContent
    from app.services.scheduler import retention_job

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)

    session = factory()
    event = Interaction(
        request_id="tw_0000000000000009",
        timestamp="2026-08-19T00:00:00Z",
        event_type="input",
        policy_id="policy-a",
        policy_name="p",
        blocked=False,
        transformed=False,
        latency_ms=1.0,
        content_available=True,
    )
    session.add(event)
    session.flush()
    session.add(
        InteractionContent(
            interaction_id=event.id,
            input_json=[{"content": "secret"}],
            byte_size=10,
            captured_at=datetime.now(UTC) - timedelta(days=2),
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
    )
    session.commit()
    session.close()

    async def _main() -> None:
        job = retention_job(factory, interval_seconds=3600)
        await job.run()

    asyncio.run(_main())

    session = factory()
    try:
        assert session.query(InteractionContent).count() == 0
        assert session.query(Interaction).one().content_available is False
    finally:
        session.close()


def test_the_scheduler_is_documented_as_single_process():
    """With several workers each would run its own copy. The jobs are
    idempotent so that is survivable rather than correct, and it should be
    stated rather than discovered."""
    import pathlib

    source = pathlib.Path("app/services/scheduler.py").read_text()

    assert "Single process only" in source


def test_stop_waits_for_an_in_flight_threaded_job():
    """Cancelling an await on asyncio.to_thread does not stop the worker
    thread; it detaches it. So gather() returned and the caller disposed the
    database engine underneath a live session — the exact shutdown race the
    method claimed to prevent while causing it."""
    import threading
    import time

    finished = threading.Event()
    started = threading.Event()

    async def _run() -> None:
        def _slow() -> None:
            started.set()
            time.sleep(0.3)
            finished.set()

        await asyncio.to_thread(_slow)

    async def _main() -> bool:
        scheduler = Scheduler()
        scheduler.start([Job(name="slow", interval_seconds=3600, run=_run)])
        await asyncio.sleep(0.05)
        assert started.is_set(), "the job did not start"
        await scheduler.stop(timeout_seconds=5)
        # Checked the moment stop() returns, not after the event loop has been
        # torn down: a detached thread finishes on its own shortly afterwards,
        # so asserting later passes even when stop() did not wait.
        return finished.is_set()

    assert asyncio.run(_main()), "stop() returned while the worker thread was still running"


def test_stop_waits_for_a_tracked_worker_past_the_task_timeout():
    """Cancelling the task only unblocks the loop; the thread keeps its session.

    My previous test for the overrun case explicitly required the unsafe
    behaviour: it measured only that stop() returned promptly, never whether
    the worker was still running, so it would have passed while shutdown
    disposed the engine underneath live database work.
    """
    import threading
    import time

    finished = threading.Event()

    async def _run(sched) -> None:
        def _slow() -> None:
            time.sleep(0.4)
            finished.set()

        await sched.run_in_worker(_slow)

    async def _main() -> bool:
        scheduler = Scheduler()
        scheduler.start([Job(name="slow", interval_seconds=3600, run=lambda: _run(scheduler))])
        await asyncio.sleep(0.05)
        # Task timeout far shorter than the worker.
        await scheduler.stop(timeout_seconds=0.05)
        return finished.is_set()

    assert asyncio.run(_main()), "stop() returned while a tracked worker was still holding a session"
