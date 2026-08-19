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
    """Two real processes, for what an in-process test cannot show.

    A second open() in this process does get its own open file description and
    does conflict -- the first test in this file proves that. What only a real
    process shows is the kernel releasing the lock when the holder dies, which
    is the property the abandonment sweep depends on.
    """
    db = tmp_path / "b.db"
    holder = subprocess.Popen([sys.executable, "-c", _holder_script(db)], stdout=subprocess.PIPE, text=True)
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


def test_the_lock_is_taken_before_any_database_access(tmp_path):
    """Including the read-only bootstrap probe and the Alembic migration.

    A migration running before the lock is a second writer by another name, and
    a read taken while another process writes is exactly what the lock exists to
    order. This asserts the ORDER, which inspection cannot guarantee stays true.

    Arranged so the probe actually runs: BOOTSTRAP_KEY is UNSET and the database
    already holds a key. With the key set, `not BOOTSTRAP_KEY and not probe()`
    short-circuits and never touches the database at all -- which is how an
    earlier version of this test passed against the wrong ordering.
    """
    import asyncio
    import sqlite3
    import sqlite3.dbapi2
    import subprocess
    from unittest.mock import patch

    from app.auth.key_utils import generate_key, hash_key, key_prefix
    from app.main import create_app, lifespan

    db = tmp_path / "order.db"

    # Migrate and seed a key, in a separate process so this one holds no lock.
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=dict(os.environ, DB_URL=f"sqlite:///{db}"),
        capture_output=True,
        check=True,
    )
    raw = generate_key(prefix="ak")
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO api_keys (id, name, key_hash, key_prefix, role, created_at) "
            "VALUES ('k1', 'seed', ?, ?, 'admin', '2026-08-19 00:00:00.000000')",
            (hash_key(raw), key_prefix(raw)),
        )

    events: list[str] = []
    real_connect = sqlite3.dbapi2.connect

    def _record_connect(*args, **kwargs):
        if str(db) in str(args[0] if args else ""):
            events.append("db")
        return real_connect(*args, **kwargs)

    real_acquire = ProcessLock.acquire

    def _record_acquire(self, db_url):
        events.append("lock")
        return real_acquire(self, db_url)

    async def _run():
        app = create_app()
        ctx = lifespan(app)
        await ctx.__aenter__()
        await ctx.__aexit__(None, None, None)

    env = {"DB_URL": f"sqlite:///{db}"}
    with patch.dict(os.environ, env, clear=False):
        os.environ.pop("BOOTSTRAP_KEY", None)
        # Both names: sqlite3/__init__.py does `from sqlite3.dbapi2 import *`,
        # so sqlite3.connect and sqlite3.dbapi2.connect are separate attributes
        # and SQLAlchemy's pysqlite dialect calls the latter.
        with patch.object(sqlite3, "connect", _record_connect):
            with patch.object(sqlite3.dbapi2, "connect", _record_connect):
                with patch.object(ProcessLock, "acquire", _record_acquire):
                    asyncio.run(_run())

    assert "db" in events, "the probe never connected, so this proves nothing"
    assert events[0] == "lock", f"the database was touched before the lock: {events[:3]}"


def test_a_refused_bootstrap_releases_the_lock(tmp_path):
    """A refused startup must not leave the database locked against the next
    attempt."""
    import asyncio
    from unittest.mock import patch

    import pytest as _pytest

    from app.main import create_app, lifespan

    db = tmp_path / "refused.db"
    env = {"DB_URL": f"sqlite:///{db}"}

    async def _run():
        app = create_app()
        await lifespan(app).__aenter__()

    with patch.dict(os.environ, env, clear=False):
        os.environ.pop("BOOTSTRAP_KEY", None)
        with _pytest.raises(RuntimeError, match="BOOTSTRAP_KEY"):
            asyncio.run(_run())

    # The next attempt must be able to take it.
    after = ProcessLock()
    after.acquire(f"sqlite:///{db}")
    after.release()
