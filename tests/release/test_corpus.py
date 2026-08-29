"""In-flight capture, and the false green that requires it.

The claim under test is narrow and was wrong once: that scanning artifacts
after the last connection closes finds anything that reached disk. It does not.
Closing checkpoints the latest page image and removes the WAL, so a committed
frame that physically held the value is gone before anything looks.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from tests.release.corpus import capture_in_flight, capture_with_reader


def _wal_database(tmp_path: Path) -> Path:
    db = tmp_path / "subject.db"
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")  # frames stay until we say
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute("CREATE TABLE t (v TEXT)")
    conn.commit()
    conn.close()
    return db


def test_after_close_capture_misses_a_wal_resident_canary(tmp_path: Path):
    """The measured false green.

    A value committed to the WAL and then removed is physically present before
    close and absent from every artifact after it. A sweep that only looks
    afterwards reports nothing and is believed.
    """
    db = _wal_database(tmp_path)
    canary = b"CANARY-WAL-RESIDENT-3f9c"

    conn = sqlite3.connect(db)
    # PRAGMAs are PER CONNECTION. Setting secure_delete only on the creating
    # connection left the deleted bytes in place, and the canary survived to
    # post-close -- so the test failed on its own premise rather than passing
    # vacuously, which is what the premise assertion is for.
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("INSERT INTO t(v) VALUES (?)", (canary.decode(),))
    conn.commit()

    with capture_with_reader(db) as reader:
        in_flight = reader.capture(tmp_path / "cap")

    conn.execute("DELETE FROM t")
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    conn.execute("VACUUM")
    conn.close()

    after = capture_in_flight(db, tmp_path / "cap", label="post-close")

    found_in_flight = sum(in_flight.occurrences(canary).values())
    found_after = sum(after.occurrences(canary).values())

    assert found_in_flight > 0, in_flight.occurrences(canary)
    assert found_after == 0, (
        "this test's premise has changed: the canary survived to post-close, so "
        "in-flight capture is no longer the only thing that sees it"
    )


def test_in_flight_capture_takes_every_sidecar_that_exists(tmp_path: Path):
    """The WAL is not optional evidence.

    Capturing only the main file reads the checkpointed image and misses
    everything still in frames.
    """
    db = _wal_database(tmp_path)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("INSERT INTO t(v) VALUES ('x')")
    conn.commit()

    with capture_with_reader(db) as reader:
        captured = reader.capture(tmp_path / "cap")

    kinds = {a.kind for a in captured.artifacts}
    assert "db" in kinds
    assert "wal" in kinds, f"the WAL was not captured: {kinds}"
    conn.close()


def _canary_committed(tmp_path: Path, canary: bytes, name: str):
    """A database whose LIVE image still holds *canary*, WAL not checkpointed.

    The delete is deliberately NOT done here. An earlier version inserted and
    deleted before the reader was opened, so the reader's snapshot was the
    post-delete one and had no need of the frame carrying the canary -- the
    truncation was blocked only because SQLite waits for any open reader, not
    because that reader pinned the relevant frame. The test passed for a
    reason its own docstring did not describe.
    """
    root = tmp_path / name
    root.mkdir()
    db = _wal_database(root)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("INSERT INTO t(v) VALUES (?)", (canary.decode(),))
    conn.commit()
    return db, conn


def test_a_held_reader_stops_the_wal_being_checkpointed_away(tmp_path: Path):
    """Both arms, because one arm proves nothing.

    Earlier this test held a reader, ran a TRUNCATE checkpoint, and asserted
    the canary was still found. It passed with the reader removed: the
    checkpoint simply moved the canary from the WAL into the main file, and
    the sweep found it there.

    The distinguishing value is one that exists ONLY in a WAL frame -- and the
    reader must be opened BEFORE the delete, so the frame it pins is the one
    carrying the canary rather than the post-delete image.
    """
    canary = b"CANARY-READER-PIN-7a21"

    # Arm 1: the reader's snapshot is taken while the canary is still live,
    # so the frame carrying it is one the reader may still need.
    db_held, conn_held = _canary_committed(tmp_path, canary, "held")
    with capture_with_reader(db_held) as reader:
        conn_held.execute("DELETE FROM t")
        conn_held.commit()
        conn_held.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        held = reader.capture(tmp_path / "held-cap")
    conn_held.close()

    # Arm 2: identical exercise, no reader open across the delete.
    db_free, conn_free = _canary_committed(tmp_path, canary, "free")
    conn_free.execute("DELETE FROM t")
    conn_free.commit()
    conn_free.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    unheld = capture_in_flight(db_free, tmp_path / "free-cap")
    conn_free.close()

    held_counts = held.occurrences(canary)
    unheld_counts = unheld.occurrences(canary)

    assert sum(held_counts.values()) > 0, f"the pinned capture lost the canary: {held_counts}"
    assert any(k.endswith(":wal") for k, v in held_counts.items() if v), (
        f"the canary survived, but not in a WAL frame: {held_counts}; the reader "
        "is not pinning what this test claims it pins"
    )
    assert sum(unheld_counts.values()) == 0, (
        "premise changed: the canary survived a TRUNCATE checkpoint without a "
        f"reader, so this no longer isolates what the reader does: {unheld_counts}"
    )


def test_occurrences_reports_per_artifact_counts(tmp_path: Path):
    """Counts, not a boolean.

    The capture-on cardinality rule needs to know how many copies exist and
    where, not merely that the value was seen somewhere.
    """
    db = _wal_database(tmp_path)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("INSERT INTO t(v) VALUES ('CANARY-COUNT-1b4d')")
    conn.commit()

    with capture_with_reader(db) as reader:
        captured = reader.capture(tmp_path / "cap")

    counts = captured.occurrences(b"CANARY-COUNT-1b4d")
    assert counts, "no artifact was searched"
    assert all(isinstance(v, int) for v in counts.values())
    assert sum(counts.values()) >= 1
    conn.close()


def test_occurrences_counts_repeats_within_one_artifact(tmp_path: Path):
    """Cardinality, not presence.

    Step 5's capture-on rule asserts an EXACT count against the canonical live
    image. A presence boolean satisfies every single-occurrence test and makes
    that rule unenforceable.
    """
    db = _wal_database(tmp_path)
    canary = b"CANARY-REPEATED-5c07"

    conn = sqlite3.connect(db)
    conn.execute("PRAGMA wal_autocheckpoint=0")
    for i in range(3):
        conn.execute("INSERT INTO t(v) VALUES (?)", (f"{canary.decode()}-{i}",))
    conn.commit()

    with capture_with_reader(db) as reader:
        captured = reader.capture(tmp_path / "cap")

    total = sum(captured.occurrences(canary).values())
    assert total >= 3, f"expected at least the three rows written, got {total}: {captured.occurrences(canary)}"
    conn.close()
