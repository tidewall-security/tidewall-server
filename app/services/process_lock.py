"""One live server per database.

Content export abandons an attempt left `pending` when its ``boot_id`` is not
the running process's, on the grounds that the process which wrote it is gone.
That is only sound if two servers cannot run against one database at a time --
and during an overlapping startup, a rolling replacement, two instances pointed
at one file, or an accidentally multi-worker launch, the other process may be
submitting or settling right now. A one-worker launcher is a convention, not
exclusion.

An exclusive ``flock`` gives real exclusion. The kernel releases it when the
holding process exits, crashes or is killed, so there is no lease, no heartbeat,
no clock, and nothing to get wrong about liveness.

Where ``flock`` is weak, it is weak in the DANGEROUS direction, and an earlier
version of this note claimed the opposite. On some network filesystems it is
advisory-only or emulated, and two instances can then both acquire it -- not
"fail to start", but "both believe they are the only one". That matters here
beyond ordinary write safety: a second live process makes the boot_id
abandonment rule wrong, because each will treat the other's in-flight export
attempts as belonging to a process that is gone.

SQLite is already unsafe on those filesystems, so this adds no new exposure.
But the database must live on local storage, and that requirement is now
load-bearing for correctness rather than performance.
"""

from __future__ import annotations

import fcntl
import os
import uuid

from sqlalchemy.engine import make_url


class ProcessLockHeld(RuntimeError):
    """Another process already holds this database."""


class ProcessLock:
    """An exclusive lock on the database, held for the process lifetime.

    Four rules, because "at startup" is not a protocol and the ownership proof
    rests on all of them:

    - **Before anything touches the database.** Acquisition precedes the Alembic
      migration, any engine use, any use of ``boot_id``, and the start of the
      abandonment sweep. A migration running before the lock is a second writer
      by another name.
    - **Held by the same open file description** until every request and
      scheduler task has drained. Closing it earlier would let a replacement
      start while this process is still settling rows.
    - **Acquired in each worker, after any fork.** A lock taken by a pre-fork
      parent is *inherited* through the same open file description, so every
      worker holds it and none of them conflicts -- the exclusion silently
      evaporates in exactly the multi-worker launch it exists to catch.
    - **Keyed to the canonical database path**, so two spellings of one database
      cannot produce two lockfiles.
    """

    def __init__(self) -> None:
        # Per instance and unguessable, so a recycled identifier cannot make an
        # old attempt row permanently immune to the sweep.
        self.boot_id = str(uuid.uuid4())
        self.path: str | None = None
        self._fd: int | None = None

    def acquire(self, db_url: str) -> None:
        self.path = self._lock_path(db_url)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise ProcessLockHeld(
                f"Another Tidewall server already holds {self.path}. Stop it before "
                "starting this one: two servers against one SQLite database are not "
                "supported, and a rolling replacement must stop the old instance first."
            ) from exc
        self._fd = fd

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    @staticmethod
    def _lock_path(db_url: str) -> str:
        """Keyed to the canonical database path.

        Two symlinks, or a relative and an absolute spelling of one database,
        would otherwise produce two lockfiles and two live servers.
        """
        url = make_url(db_url)
        database = url.database or ""
        if not database or database == ":memory:":
            # An in-memory database is per-process by construction, so there is
            # nothing to exclude; give each one its own file so tests and
            # embedded uses do not contend over a shared name.
            return os.path.join("/tmp", f"tidewall-memory-{uuid.uuid4().hex}.lock")
        return os.path.realpath(database) + ".lock"
