"""One live server per database.

Content export abandons a `pending` attempt when its boot_id is not this
process's, on the grounds that the process which wrote it is gone. That is only
true if two servers cannot run against one database at a time, and a one-worker
launcher is a convention rather than exclusion.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

from app.services.process_lock import ProcessLock, ProcessLockHeld

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_a_second_lock_on_the_same_database_is_refused(tmp_path):
    db = tmp_path / "a.db"
    first = ProcessLock()
    first.acquire(f"sqlite:///{db}")
    try:
        with pytest.raises(ProcessLockHeld):
            ProcessLock().acquire(f"sqlite:///{db}")
    finally:
        first.release()


def test_aliased_paths_resolve_to_one_lockfile(tmp_path):
    """Two symlinks, or a relative and an absolute spelling, would otherwise
    produce two lockfiles and two live servers."""
    real = tmp_path / "real.db"
    real.write_text("")
    link = tmp_path / "link.db"
    link.symlink_to(real)

    first = ProcessLock()
    first.acquire(f"sqlite:///{real}")
    try:
        with pytest.raises(ProcessLockHeld):
            ProcessLock().acquire(f"sqlite:///{link}")
    finally:
        first.release()


def test_boot_id_is_unique_per_instance():
    # Unguessable, so a recycled identifier cannot make an old attempt row
    # permanently immune to the sweep.
    assert ProcessLock().boot_id != ProcessLock().boot_id


def _holder_script(db_path):
    return textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {ROOT!r})
        from app.services.process_lock import ProcessLock
        lock = ProcessLock()
        lock.acquire("sqlite:///{db_path}")
        print("HELD", flush=True)
        time.sleep(30)
    """)


def test_a_second_process_is_refused_then_succeeds_once_the_first_exits(tmp_path):
    """Two real processes. An in-process test shares a file descriptor table and
    cannot exhibit the conflict a second server actually hits."""
    db = tmp_path / "b.db"
    holder = subprocess.Popen(
        [sys.executable, "-c", _holder_script(db)], stdout=subprocess.PIPE, text=True
    )
    try:
        assert holder.stdout.readline().strip() == "HELD"
        with pytest.raises(ProcessLockHeld):
            ProcessLock().acquire(f"sqlite:///{db}")
    finally:
        holder.terminate()
        holder.wait(timeout=10)

    # The kernel released it when the holder died: no lease, no heartbeat.
    after = ProcessLock()
    after.acquire(f"sqlite:///{db}")
    after.release()
