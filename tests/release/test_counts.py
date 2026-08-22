"""The two count rules, and every arm of the historical pass condition."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from tests.release.corpus import Artifact, ArtifactSet, capture_with_reader
from tests.release.counts import (
    CountViolation,
    Measured,
    canonical_live_image,
    check_capture_off,
    check_capture_on,
    check_historical,
    measure,
)
from tests.release.occurrences import Rule

SECRET = b"CANARY-COUNT-RULE-6f28"


def _db(tmp_path: Path, name: str = "subject.db") -> Path:
    db = tmp_path / name
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE policies (id INTEGER PRIMARY KEY, name TEXT UNIQUE)")
    conn.commit()
    conn.close()
    return db


def _fake(kind: str, moment: str, data: bytes, tmp_path: Path) -> Artifact:
    p = tmp_path / f"{moment}-{kind}"
    p.write_bytes(data)
    return Artifact(p, kind, moment)


# --- capture-off ------------------------------------------------------------


def test_capture_off_fails_on_any_live_occurrence(tmp_path: Path):
    m = Measured(live={"in-flight:db": 1}, historical={})
    with pytest.raises(CountViolation, match="capture-off expects zero"):
        check_capture_off(m)


def test_capture_off_fails_on_a_historical_occurrence_too(tmp_path: Path):
    """No 'it was only in the WAL' excuse.

    With capture off nothing was ever supposed to write the value, so a
    superseded page image holding it is a write that happened.
    """
    m = Measured(live={}, historical={"in-flight:wal": 1})
    with pytest.raises(CountViolation, match="capture-off expects zero"):
        check_capture_off(m)


def test_capture_off_passes_when_nothing_is_found():
    check_capture_off(Measured(live={}, historical={}))


# --- capture-on -------------------------------------------------------------


def test_capture_on_requires_the_exact_copy_map_count(tmp_path: Path):
    """A unique column holds its value twice."""
    conn = sqlite3.connect(_db(tmp_path))
    check_capture_on(conn, ("policies", "name"), canonical_count=2)
    conn.close()


def test_capture_on_rejects_an_under_count(tmp_path: Path):
    conn = sqlite3.connect(_db(tmp_path))
    with pytest.raises(CountViolation, match="under-count"):
        check_capture_on(conn, ("policies", "name"), canonical_count=1)
    conn.close()


def test_capture_on_rejects_an_over_count(tmp_path: Path):
    """An extra copy is a leak, not a rounding error."""
    conn = sqlite3.connect(_db(tmp_path))
    with pytest.raises(CountViolation, match="over-count"):
        check_capture_on(conn, ("policies", "name"), canonical_count=3)
    conn.close()


def test_the_canonical_image_matches_the_copy_map_on_real_bytes(tmp_path: Path):
    """The rule against a real database, not a hand-supplied number.

    This is the assertion that would catch the copy map being wrong about
    physical reality rather than merely self-consistent.
    """
    db = _db(tmp_path)
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO policies(id, name) VALUES (1, ?)", (SECRET.decode(),))
    conn.commit()
    conn.close()

    image = canonical_live_image(db, tmp_path / "canonical" / "image.db")
    actual = image.read_bytes().count(SECRET)

    conn = sqlite3.connect(db)
    check_capture_on(conn, ("policies", "name"), canonical_count=actual)
    conn.close()


def test_the_canonical_image_carries_no_history(tmp_path: Path):
    """Checkpointed and vacuumed, or the count measures churn.

    A value written and deleted survives in the working database's WAL and
    freed pages. It must not survive into the canonical image.
    """
    db = _db(tmp_path)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("INSERT INTO policies(id, name) VALUES (1, ?)", (SECRET.decode(),))
    conn.commit()

    with capture_with_reader(db) as reader:
        working = reader.capture(tmp_path / "working")
    conn.execute("DELETE FROM policies")
    conn.commit()
    conn.close()

    assert (
        sum(measure(working, SECRET).historical.values()) > 0
    ), "premise changed: the working database never held the value historically"

    image = canonical_live_image(db, tmp_path / "canonical" / "image.db")
    assert image.read_bytes().count(SECRET) == 0, "the canonical image still carries a deleted value"


# --- historical -------------------------------------------------------------


def _hist(tmp_path: Path) -> Measured:
    captured = ArtifactSet(
        artifacts=[
            _fake("db", "in-flight", b"nothing here", tmp_path),
            _fake("wal", "in-flight", b"..." + SECRET + b"...", tmp_path),
        ]
    )
    return measure(captured, SECRET)


def test_a_historical_occurrence_is_permitted_when_the_live_path_allows_it(tmp_path):
    check_historical(
        _hist(tmp_path),
        live_rule=Rule.ALLOWED_BOUNDED,
        live_count=1,
        same_database_file=True,
    )


def test_required_at_the_live_path_also_permits_history(tmp_path):
    check_historical(_hist(tmp_path), live_rule=Rule.REQUIRED, live_count=1, same_database_file=True)


def test_a_historical_occurrence_of_a_value_with_no_live_occurrence_fails(tmp_path):
    """Nothing live justifies the residue."""
    with pytest.raises(CountViolation, match="no live occurrence"):
        check_historical(
            _hist(tmp_path),
            live_rule=Rule.ALLOWED_BOUNDED,
            live_count=0,
            same_database_file=True,
        )


def test_a_historical_occurrence_forbidden_at_its_live_path_fails(tmp_path):
    """History does not launder a value that was never allowed to rest there."""
    with pytest.raises(CountViolation, match="FORBIDDEN at its live path"):
        check_historical(
            _hist(tmp_path),
            live_rule=Rule.FORBIDDEN,
            live_count=1,
            same_database_file=True,
        )


def test_a_historical_occurrence_in_another_database_file_fails(tmp_path):
    with pytest.raises(CountViolation, match="different database file"):
        check_historical(
            _hist(tmp_path),
            live_rule=Rule.REQUIRED,
            live_count=1,
            same_database_file=False,
        )


def test_historical_duplicates_are_not_counted(tmp_path):
    """Permitted or not; there is no cardinality to assert.

    How many superseded page images hold a value is page churn, not behaviour.
    """
    many = ArtifactSet(artifacts=[_fake("wal", "in-flight", SECRET * 17, tmp_path)])
    check_historical(
        measure(many, SECRET),
        live_rule=Rule.ALLOWED_BOUNDED,
        live_count=1,
        same_database_file=True,
    )


def test_no_historical_occurrence_is_trivially_fine(tmp_path):
    check_historical(
        Measured(live={"in-flight:db": 2}, historical={}),
        live_rule=Rule.FORBIDDEN,
        live_count=0,
        same_database_file=False,
    )


def test_measure_splits_live_from_historical(tmp_path: Path):
    captured = ArtifactSet(
        artifacts=[
            _fake("db", "in-flight", SECRET, tmp_path),
            _fake("wal", "in-flight", SECRET + SECRET, tmp_path),
        ]
    )
    m = measure(captured, SECRET)
    assert m.live == {"in-flight:db": 1}
    assert m.historical == {"in-flight:wal": 2}


def test_a_plain_file_copy_still_carries_a_deleted_value(tmp_path: Path):
    """Why the canonical image is a VACUUM and not a copy.

    With secure_delete off, a deleted row's bytes stay in a freeblock of the
    main database file. A byte copy of that file counts them; the rebuilt
    image does not. An earlier version of this suite only ever deleted with
    secure_delete ON, so a plain copy passed every test.
    """
    db = tmp_path / "leaky.db"
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA secure_delete=OFF")
    conn.execute("CREATE TABLE t (v TEXT)")
    conn.execute("INSERT INTO t(v) VALUES (?)", (SECRET.decode(),))
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    conn.execute("DELETE FROM t")
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    conn.close()

    assert db.read_bytes().count(SECRET) > 0, (
        "premise changed: the main file no longer retains the deleted bytes, "
        "so this no longer distinguishes a copy from a rebuild"
    )

    image = canonical_live_image(db, tmp_path / "canonical" / "image.db")
    assert image.read_bytes().count(SECRET) == 0, "the rebuilt image carried a freeblock the live database still holds"


def test_an_unrecognised_live_rule_fails_closed(tmp_path: Path):
    """A rule the historical condition has no answer for is not a pass.

    If a fourth verdict is ever added to Rule, every historical occurrence
    under it must fail here until someone decides what it means.
    """
    with pytest.raises(CountViolation, match="unhandled rule"):
        check_historical(
            _hist(tmp_path),
            live_rule="PROVISIONAL",
            live_count=1,
            same_database_file=True,
        )
