"""The cancellation-resistant join used for settlement and cleanup.

Rendezvous is by event where the ordering matters -- "the task has started",
"the joiner is waiting" -- so those points are exact. Some tasks then run for a
short fixed sleep to give the joiner something to wait on; that is duration,
not synchronisation, and no assertion depends on how long it takes.

These test the helper. They say nothing about whether the route calls it:
that is tests/test_content_export_cancellation.py, and the two were separately
necessary -- both call sites were replaceable with a plain await while every
test here stayed green.
"""

from __future__ import annotations

import asyncio

import pytest

from app.routes.content_export import _join_and_drain


def _run(coro):
    return asyncio.run(coro)


def test_a_result_is_retrieved():
    async def _go():
        task = asyncio.create_task(asyncio.sleep(0, result="done"))
        errors: list[Exception] = []
        cancelled = await _join_and_drain(task, on_error=errors.append)
        return cancelled, errors, task.result()

    cancelled, errors, result = _run(_go())
    assert cancelled is False
    assert errors == []
    assert result == "done"


def test_an_exception_is_handed_to_on_error_exactly_once():
    """The shield re-raises whatever the task raised. Before the loop caught
    that, the exception escaped the join entirely -- skipping the drain and, for
    settlement, skipping cleanup."""

    async def _boom():
        raise RuntimeError("settlement failed")

    async def _go():
        task = asyncio.create_task(_boom())
        errors: list[Exception] = []
        cancelled = await _join_and_drain(task, on_error=errors.append)
        return cancelled, errors

    cancelled, errors = _run(_go())
    assert cancelled is False
    assert len(errors) == 1, f"handled {len(errors)} times"
    assert isinstance(errors[0], RuntimeError)


def test_the_exception_does_not_escape_the_join():
    """Directly: the caller must reach its cleanup, not unwind."""
    reached = []

    async def _boom():
        raise RuntimeError("settlement failed")

    async def _go():
        task = asyncio.create_task(_boom())
        await _join_and_drain(task, on_error=lambda exc: None)
        reached.append("after")

    _run(_go())
    assert reached == ["after"], "the join let the task's exception escape"


def test_a_cancellation_during_the_wait_is_deferred_not_obeyed():
    """The task must finish; the cancellation is reported for the caller to
    re-raise after cleanup."""
    started = asyncio.Event()
    finished = []

    async def _slow():
        started.set()
        await asyncio.sleep(0.05)
        finished.append("done")

    async def _go():
        task = asyncio.create_task(_slow())
        await started.wait()

        async def _joiner():
            return await _join_and_drain(task, on_error=lambda exc: None)

        joiner = asyncio.create_task(_joiner())
        await asyncio.sleep(0)
        joiner.cancel()
        return await joiner

    cancelled = _run(_go())
    assert cancelled is True, "the cancellation was not reported"
    assert finished == ["done"], "the task was abandoned"


def test_the_task_is_never_cancelled_by_the_join():
    started = asyncio.Event()

    async def _slow():
        started.set()
        await asyncio.sleep(0.05)

    async def _go():
        task = asyncio.create_task(_slow())
        await started.wait()

        async def _joiner():
            return await _join_and_drain(task, on_error=lambda exc: None)

        joiner = asyncio.create_task(_joiner())
        await asyncio.sleep(0)
        joiner.cancel()
        await joiner
        return task

    task = _run(_go())
    assert not task.cancelled(), "the join cancelled the task it was waiting for"
    assert task.done()


def test_a_task_that_completes_on_the_cancelling_tick_still_has_its_result_drained():
    """The completion race the drain exists for.

    The loop can exit on the tick where the shield raised and the task
    completed, having retrieved nothing -- so a failure would go unobserved and
    its outcome unapplied.
    """
    errors: list[Exception] = []
    gate = asyncio.Event()

    async def _boom():
        await gate.wait()
        raise RuntimeError("failed at the last moment")

    async def _go():
        task = asyncio.create_task(_boom())

        async def _joiner():
            return await _join_and_drain(task, on_error=errors.append)

        joiner = asyncio.create_task(_joiner())
        await asyncio.sleep(0)
        # Release the task and cancel the joiner on the same tick.
        gate.set()
        joiner.cancel()
        return await joiner

    cancelled = _run(_go())
    assert cancelled is True
    assert len(errors) == 1, "the task's exception was never retrieved"


def test_the_join_holds_its_own_reference_to_the_task():
    """A bare create_task is owned by nothing but the loop's weak set.

    An earlier version of this test kept the task in a local of its own and
    then called gc.collect(), which could only ever prove that a strongly
    referenced object is not collected. The caller here drops every reference
    it has before collecting, so the only thing keeping the task alive is the
    join's own parameter.

    Ownership by the *process* is a different property with a different test:
    test_the_settlement_task_is_always_owned_by_the_process, in
    tests/test_content_export_cancellation.py.
    """
    import gc

    async def _go():
        errors: list[Exception] = []
        result: list[object] = []

        async def _work():
            await asyncio.sleep(0.01)
            result.append("kept")

        async def _join_only(task):
            # The task is now reachable from this frame's argument and from
            # nowhere else the caller controls.
            gc.collect()
            gc.collect()
            return await _join_and_drain(task, on_error=errors.append)

        joiner = _join_only(asyncio.create_task(_work()))
        cancelled = await joiner
        return cancelled, errors, result

    cancelled, errors, result = _run(_go())
    assert result == ["kept"], "the task did not run to completion"
    assert errors == []
    assert cancelled is False


@pytest.mark.parametrize("attempts_count", [1, 5])
def test_repeated_cancellation_is_absorbed(attempts_count):
    started = asyncio.Event()
    finished = []

    async def _slow():
        started.set()
        await asyncio.sleep(0.05)
        finished.append("done")

    async def _go():
        task = asyncio.create_task(_slow())
        await started.wait()

        async def _joiner():
            return await _join_and_drain(task, on_error=lambda exc: None)

        joiner = asyncio.create_task(_joiner())
        for _ in range(attempts_count):
            await asyncio.sleep(0)
            joiner.cancel()
        return await joiner

    cancelled = _run(_go())
    assert cancelled is True
    assert finished == ["done"], "repeated cancellation abandoned the task"
