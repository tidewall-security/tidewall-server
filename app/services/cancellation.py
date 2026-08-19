"""Joining a task without letting a cancellation abandon it.

Shared by the content-export route and the sender beneath it, because the same
hazard appears at three points on that path: the settlement that records a
disclosure, the cleanup that closes the connection carrying it, and the close
that has to happen when a cancellation lands mid-submission, before either of
the other two exists.
"""

from __future__ import annotations

import asyncio
from typing import Any


async def join_and_drain(task: asyncio.Task, *, on_error: Any) -> bool:
    """Wait for a task without letting a cancellation abandon it.

    A plain ``await`` is not enough: a cancel arriving *during* it unwinds the
    caller and leaves the task running unobserved. Shield in a loop, remember
    every cancellation rather than obeying it, and only then drain.

    The drain is not optional. The loop can exit on the tick where the shield
    raised and the task completed, having retrieved nothing -- so a failure would
    go unobserved and its outcome unapplied.

    Returns whether a cancellation was deferred.
    """
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            # The shield re-raises whatever the task raised. Letting that
            # propagate here would skip the drain below and, for settlement,
            # skip cleanup entirely -- so it is swallowed at this point and
            # handled once, from task.result().
            break
    try:
        task.result()
    except asyncio.CancelledError:
        # Deferred, not obeyed. Re-raising here would skip the cleanup that
        # follows and leak the connection -- the case cleanup exists for.
        cancelled = True
    except Exception as exc:
        on_error(exc)
    return cancelled
