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


def test_a_scheduler_that_cannot_start_does_not_stop_the_server(tmp_path):
    """Installing retention is capture-only work, so it cannot decide whether
    the server serves.

    Unguarded, an import or task-creation failure aborted startup even with
    capture disabled on every policy: no enforcement at all, because of a
    subsystem with nothing to do. Content is not left exposed by this — the
    read gate denies expired content whether or not a purge ever ran — but
    expired rows do stay on disk, so it must be loud.
    """
    import asyncio
    import logging
    import os
    from unittest.mock import patch

    import app.services.scheduler as scheduler_module
    from app.main import create_app, lifespan

    db = tmp_path / "sched.db"
    env = {"DB_URL": f"sqlite:///{db}", "BOOTSTRAP_KEY": "test-bootstrap-key-0123456789"}

    def _explode(*_args, **_kwargs):
        raise RuntimeError("scheduler unavailable")

    async def _startup_then_shutdown():
        app = create_app()
        ctx = lifespan(app)
        await ctx.__aenter__()
        try:
            # Startup completed, so the server would begin accepting requests.
            assert app.state.scheduler is None
            assert app.state.interaction_log is not None
        finally:
            await ctx.__aexit__(None, None, None)

    # Captured at the call, not at a handler: Alembic runs fileConfig during
    # startup migrations, which replaces the root handlers — so caplog and any
    # handler attached beforehand see nothing.
    records: list[str] = []
    real_error = logging.Logger.error

    def _record(self, msg, *args, **kwargs):
        records.append(str(msg))
        return real_error(self, msg, *args, **kwargs)

    with patch.dict(os.environ, env, clear=False):
        with patch.object(scheduler_module, "Scheduler", _explode):
            with patch.object(logging.Logger, "error", _record):
                asyncio.run(_startup_then_shutdown())

    assert any(
        "retention scheduler did not start" in m for m in records
    ), "a scheduler that failed to start did so quietly"


def test_a_scheduler_that_cannot_stop_does_not_break_shutdown(tmp_path):
    """Stopping retention is capture-only work too.

    Unguarded, an exception from stop() escaped lifespan teardown and skipped
    engine.dispose() entirely — capture deciding whether the server shuts down
    cleanly. A raising stop() also means we cannot know whether a worker still
    owns a session, so it must count as *not* drained: the same conservative
    answer stop() gives when it times out, and the same consequence — do not
    dispose the engine out from under a worker that may still hold a session.
    """
    import asyncio
    import logging
    import os
    from unittest.mock import patch

    from sqlalchemy.engine import Engine

    import app.services.scheduler as scheduler_module
    from app.main import create_app, lifespan

    db = tmp_path / "sched_stop.db"
    env = {"DB_URL": f"sqlite:///{db}", "BOOTSTRAP_KEY": "test-bootstrap-key-0123456789"}

    async def _explode(self):
        raise RuntimeError("stop failed")

    records: list[str] = []
    real_error = logging.Logger.error

    def _record(self, msg, *args, **kwargs):
        records.append(str(msg))
        return real_error(self, msg, *args, **kwargs)

    disposals: list[int] = []
    real_dispose = Engine.dispose

    def _count_dispose(self, *args, **kwargs):
        disposals.append(1)
        return real_dispose(self, *args, **kwargs)

    async def _startup_then_shutdown():
        app = create_app()
        ctx = lifespan(app)
        await ctx.__aenter__()
        disposals.clear()  # ignore anything migrations disposed during startup
        with patch.object(Engine, "dispose", _count_dispose):
            # Must not raise: the scheduler cannot fail the shutdown.
            await ctx.__aexit__(None, None, None)

    with patch.dict(os.environ, env, clear=False):
        with patch.object(scheduler_module.Scheduler, "stop", _explode):
            with patch.object(logging.Logger, "error", _record):
                asyncio.run(_startup_then_shutdown())

    assert any("did not stop cleanly" in m for m in records), "a failing stop() was swallowed quietly"
    assert not disposals, "disposed the engine while a worker may still have owned a session"


def test_a_scheduler_that_fails_midway_through_start_is_still_stopped(tmp_path):
    """A partial start must not orphan its tasks.

    start() creates the job tasks and then reports. If anything after the first
    create_task() raises, dropping the scheduler reference would leave that
    task running while shutdown concludes there is no background work — and
    the decision about disposing the database engine is made on that belief.
    """
    import asyncio
    import os
    from unittest.mock import patch

    import app.services.scheduler as scheduler_module
    from app.main import create_app, lifespan

    db = tmp_path / "sched_partial.db"
    env = {"DB_URL": f"sqlite:///{db}", "BOOTSTRAP_KEY": "test-bootstrap-key-0123456789"}

    real_start = scheduler_module.Scheduler.start

    def _start_then_fail(self, jobs):
        real_start(self, jobs)  # tasks now exist
        raise RuntimeError("reporting blew up after the tasks were created")

    stopped: list[bool] = []
    real_stop = scheduler_module.Scheduler.stop

    async def _record_stop(self, **kwargs):
        stopped.append(True)
        return await real_stop(self, **kwargs)

    async def _startup_then_shutdown():
        app = create_app()
        ctx = lifespan(app)
        await ctx.__aenter__()
        scheduler = app.state.scheduler
        assert scheduler is not None, "a partially started scheduler was dropped"
        assert scheduler._tasks, "the test did not actually create any tasks"
        await ctx.__aexit__(None, None, None)
        assert not [t for t in scheduler._tasks if not t.done()], "a job task outlived shutdown"

    with patch.dict(os.environ, env, clear=False):
        with patch.object(scheduler_module.Scheduler, "start", _start_then_fail):
            with patch.object(scheduler_module.Scheduler, "stop", _record_stop):
                asyncio.run(_startup_then_shutdown())

    assert stopped, "shutdown never stopped the partially started scheduler"
