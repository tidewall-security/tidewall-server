"""The route's own settlement, through the real lifespan.

The scheduler tests construct both halves themselves -- they call
run_in_worker and add their own task to the settlement set -- so they prove the
shutdown CONSUMER, not that the producing route is connected to it. These drive
the real endpoint and then shut the real application down.

Two wirings are separately load-bearing, and each covers a window the other
does not:

* dispatching through ``scheduler.run_in_worker`` registers the THREAD. A
  cancelled ``asyncio.to_thread`` await detaches its thread rather than
  stopping it, so without the scheduler a cancelled settlement leaves a live
  writer that no drain can see -- and the lock is released, and the engine
  disposed, underneath it.
* registering the task with ``app.state.export_settlements`` covers the window
  BEFORE any worker exists. Between ``create_task`` and the task's first step
  nothing is registered with the scheduler and every worker drain reports idle,
  so the task itself is the only evidence that work is pending.

Note what does NOT hold these up: ``stop()`` drains workers itself, so once a
settlement has reached its thread the ordering survives removing the
lifespan's ``drain_workers()`` call.

Only the second and third tests isolate a mechanism, and each says which. The
first isolates nothing -- several mechanisms would independently hold its
ordering, and it passes with ``scheduler = None`` in the route.
"""

from __future__ import annotations

import asyncio
import os
import threading
from datetime import UTC, datetime
from unittest.mock import patch

from httpx import ASGITransport, AsyncClient

from app.auth.grants import CONTENT_EXPORT
from app.auth.key_utils import generate_key, hash_key, key_prefix

# How long shutdown must stay unfinished before it counts as blocked on the
# settlement. It only has to exceed the work that legitimately precedes the
# gather -- scheduler.stop() -- which is milliseconds here; the margin is
# large because the failure mode of too small a value is a flaky failure,
# while too large a value only costs this one test its own wait.
_BLOCKED_PROBE_SECONDS = 2.0


class _Harness:
    """A real app, a real lifespan, one exportable interaction, one target."""

    def __init__(self) -> None:
        self.timeline: list[str] = []
        self._lock = threading.Lock()
        self.entered = threading.Event()
        self.release = threading.Event()
        self.dispatch_gate = asyncio.Event()
        # Set by a scenario that wants the release of the lock checked against
        # a specific task, rather than against wall-clock ordering.
        self.pending_probe = None

    def record(self, event: str) -> None:
        with self._lock:
            self.timeline.append(event)

    def blocking_settle(self, real):
        def _settle(*args, **kwargs):
            self.record("settle-started")
            self.entered.set()
            self.release.wait(10)
            out = real(*args, **kwargs)
            self.record("settle-finished")
            return out

        return _settle

    def seed(self, app) -> tuple[str, int, int]:
        from app.db.models import APIKey, ExportTarget, Interaction, InteractionContent, Policy

        session = app.state.session_factory()
        session.add(Policy(id="policy-a", name="policy-a", type="application"))
        raw = generate_key(prefix="ak")
        session.add(
            APIKey(
                name="admin",
                key_hash=hash_key(raw),
                key_prefix=key_prefix(raw),
                role="admin",
                policy_id="policy-a",
                grants=[CONTENT_EXPORT],
            )
        )
        interaction = Interaction(
            request_id="tw_00000000000000aa",
            timestamp="2026-08-19T00:00:00Z",
            event_type="input",
            policy_id="policy-a",
            policy_name="policy-a",
            blocked=False,
            transformed=False,
            latency_ms=1.0,
            content_available=True,
        )
        session.add(interaction)
        session.flush()
        session.add(
            InteractionContent(
                interaction_id=interaction.id,
                policy_id="policy-a",
                input_json=[{"role": "user", "content": "prompt"}],
                byte_size=10,
                captured_at=datetime.now(UTC),
            )
        )
        target = ExportTarget(
            name="siem",
            type="webhook",
            config={"url": "https://receiver.invalid/hook"},
            format="ocsf",
            events=[],
            enabled=True,
            allow_content_export=True,
            content_export_policy_id="policy-a",
            content_export_views=["full"],
        )
        session.add(target)
        session.commit()
        out = (raw, interaction.id, target.id)
        session.close()
        return out

    def watch_lock(self, app) -> None:
        real = app.state.process_lock.release

        def _release():
            self.record("lock-released")
            if self.pending_probe is not None and not self.pending_probe.done():
                # The invariant, checked at the only instant it can be checked
                # without racing anything: when the lock goes, no settlement
                # this process started may still be waiting to run.
                self.record("lock-released-with-settlement-pending")
            return real()

        app.state.process_lock.release = _release


async def _await_worker(app, harness):
    """Hand over once the settlement is inside its thread."""
    await asyncio.to_thread(harness.entered.wait, 10)


async def _await_registration(app, harness):
    """Hand over once the task exists but before any worker does."""
    for _ in range(2000):
        if app.state.export_settlements:
            return
        await asyncio.sleep(0.005)
    raise AssertionError("the route never registered a settlement")


def _run(tmp_path, scenario, *, rendezvous=_await_worker, delay_dispatch=False):
    """Boot the real app, run `scenario`, and return the harness and app."""
    from app.main import create_app, lifespan
    from app.services.export_transport import SendResult

    harness = _Harness()
    db = tmp_path / "shutdown.db"
    env = {"DB_URL": f"sqlite:///{db}", "BOOTSTRAP_KEY": "test-bootstrap-key-0123456789"}

    async def _fake_send(**kwargs):
        return SendResult(phase="headers_received", status=204, peer="127.0.0.1")

    async def _main():
        app = create_app()
        ctx = lifespan(app)
        await ctx.__aenter__()
        harness.watch_lock(app)
        if delay_dispatch:
            # Hold the settlement in the window between create_task and its
            # first step: the task is live and registered with the process
            # while no worker exists yet and every worker drain reports idle.
            real_run_in_worker = app.state.scheduler.run_in_worker

            async def _delayed(fn):
                # ONLY the route's settlement. Delaying every dispatch also
                # stalls the scheduler's own jobs, which blocks stop() -- and a
                # shutdown held up there looks exactly like a shutdown held up
                # by the settlement drain, so the mutation it is meant to catch
                # survives.
                if getattr(fn, "__name__", "") == "_settle":
                    await harness.dispatch_gate.wait()
                return await real_run_in_worker(fn)

            app.state.scheduler.run_in_worker = _delayed
        raw, interaction_id, target_id = harness.seed(app)

        import app.routes.content_export as route
        import app.services.content_export as service

        with patch.object(
            route, "validate_destination", lambda url, posture: ("receiver.invalid", 443, ["203.0.113.5"])
        ):
            with patch.object(route, "send_payload", _fake_send):
                with patch.object(route.attempts, "settle", harness.blocking_settle(service.settle)):
                    transport = ASGITransport(app=app)
                    async with AsyncClient(transport=transport, base_url="http://test") as client:
                        request = asyncio.create_task(
                            client.post(
                                f"/v1/logs/{interaction_id}/content-export",
                                json={"view": "full", "target_id": target_id},
                                headers={"Authorization": f"Bearer {raw}"},
                            )
                        )
                        await rendezvous(app, harness)
                        assert (
                            app.state.export_settlements
                        ), "the route did not register its settlement with the process"
                        await scenario(app, ctx, harness)
                        request.cancel()
                        try:
                            await request
                        except (asyncio.CancelledError, Exception):
                            pass
        return app

    with patch.dict(os.environ, env, clear=False):
        return harness, asyncio.run(_main())


def test_shutdown_waits_for_a_settlement_the_route_started(tmp_path):
    """The end-to-end claim: a real request's settlement outranks shutdown.

    Nothing is cancelled and the settlement has already reached its thread, so
    several mechanisms would each hold this ordering on their own, and this
    kills none of them individually -- it passes with the route's scheduler
    dispatch removed. What it establishes is that a real request produces a
    settlement the real lifespan waits for at all, which no test built from
    synthetic tasks can show. The two that follow isolate the wirings.
    """

    async def scenario(app, ctx, harness):
        async def _release_soon():
            await asyncio.sleep(0.2)
            harness.release.set()

        releaser = asyncio.create_task(_release_soon())
        await ctx.__aexit__(None, None, None)
        harness.record("shutdown-returned")
        await releaser

    harness, app = _run(tmp_path, scenario)
    t = harness.timeline
    assert "settle-started" in t
    assert (
        t.index("settle-finished") < t.index("lock-released") < t.index("shutdown-returned")
    ), f"shutdown released the lock while the route's settlement was still writing: {t}"
    assert not app.state.export_settlements, "a route settlement outlived shutdown"
    assert not app.state.process_lock.held


def test_shutdown_waits_for_a_settlement_thread_whose_task_was_cancelled(tmp_path):
    """Cancel the settlement task while its thread writes.

    The task completes immediately as cancelled, so the settlement-set drain
    sails straight past it. Only the scheduler's worker registry still knows a
    thread is running -- which is the whole reason the route dispatches through
    it rather than calling asyncio.to_thread itself.
    """

    async def scenario(app, ctx, harness):
        (settle_task,) = tuple(app.state.export_settlements)
        settle_task.cancel()
        await asyncio.sleep(0)
        assert settle_task.done(), "the cancelled task should not keep the drain busy"

        async def _release_soon():
            await asyncio.sleep(0.2)
            harness.release.set()

        releaser = asyncio.create_task(_release_soon())
        await ctx.__aexit__(None, None, None)
        harness.record("shutdown-returned")
        await releaser

    harness, app = _run(tmp_path, scenario)
    t = harness.timeline
    assert "settle-finished" in t, "the detached thread never completed"
    assert t.index("settle-finished") < t.index(
        "lock-released"
    ), f"the lock was released while a detached settlement thread was still writing: {t}"
    assert not app.state.process_lock.held


def test_shutdown_waits_for_a_settlement_that_has_not_reached_a_worker(tmp_path):
    """The window the settlement set exists for.

    A settlement task that has not taken its first step has registered no
    worker, so ``stop()`` and ``drain_workers()`` both correctly report idle.
    Only membership of ``app.state.export_settlements`` says the work is
    pending. Removing the lifespan's gather over that set releases the lock and
    disposes the engine while this settlement is still to run.
    """

    async def scenario(app, ctx, harness):
        assert app.state.scheduler._workers_idle.is_set(), (
            "the settlement reached a worker before the scenario began, so this "
            "test would not exercise the pre-dispatch window"
        )
        assert not harness.entered.is_set()
        (settle_task,) = tuple(app.state.export_settlements)
        harness.pending_probe = settle_task

        # No timer releases the settlement: it stays undispatched until
        # shutdown has demonstrably either blocked on it or walked past it. An
        # earlier version released after a fixed delay, which fired while
        # stop() was still running -- so even the mutated build dispatched in
        # time to look correct.
        shutdown = asyncio.create_task(ctx.__aexit__(None, None, None))
        done, _pending = await asyncio.wait({shutdown}, timeout=_BLOCKED_PROBE_SECONDS)
        harness.record("shutdown-returned-early" if done else "shutdown-blocked")
        harness.release.set()
        harness.dispatch_gate.set()
        await shutdown
        harness.record("shutdown-returned")

    harness, app = _run(tmp_path, scenario, rendezvous=_await_registration, delay_dispatch=True)
    t = harness.timeline
    assert "shutdown-returned-early" not in t, f"shutdown did not wait for a pending settlement: {t}"
    assert (
        "lock-released-with-settlement-pending" not in t
    ), f"the lock was released with a settlement still to run: {t}"
    assert "settle-finished" in t, f"the settlement never completed: {t}"
    assert t.index("settle-finished") < t.index(
        "lock-released"
    ), f"the lock was released before a pending settlement had run: {t}"
    assert not app.state.process_lock.held
