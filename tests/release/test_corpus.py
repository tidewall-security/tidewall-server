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


def test_a_held_reader_stops_the_wal_being_checkpointed_away(tmp_path: Path):
    """Why the reader exists at all.

    Without an open snapshot, a checkpoint between the write and the copy
    truncates the WAL, and the capture reads a file that no longer holds the
    frames it was taken for.
    """
    db = _wal_database(tmp_path)
    canary = b"CANARY-READER-PIN-7a21"

    writer = sqlite3.connect(db)
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("INSERT INTO t(v) VALUES (?)", (canary.decode(),))
    writer.commit()

    with capture_with_reader(db) as reader:
        # A checkpoint attempted while the snapshot is held cannot reclaim the
        # frames the reader may still need.
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        pinned = reader.capture(tmp_path / "pinned")

    assert sum(pinned.occurrences(canary).values()) > 0, pinned.occurrences(canary)
    writer.close()


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
