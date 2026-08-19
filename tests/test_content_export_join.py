"""The cancellation-resistant join used for settlement and cleanup.

Deterministic: every case is driven by events rather than sleeps, so the
completion races are exercised exactly rather than approximately.
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


def test_the_task_reference_is_held_so_it_cannot_be_collected():
    """A bare create_task is owned by nothing; the caller must hold it."""
    import gc

    async def _go():
        task = asyncio.create_task(asyncio.sleep(0.01, result="kept"))
        gc.collect()
        await _join_and_drain(task, on_error=lambda exc: None)
        return task.result()

    assert _run(_go()) == "kept"


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
