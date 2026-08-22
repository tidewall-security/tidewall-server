"""Attribution: a byte occurrence joined to the path that explains it."""

from __future__ import annotations

import sqlite3

import pytest

from tests.release.attribution import (
    Unattributed,
    attribute,
    cells_holding,
    expected_locations,
    unexplained,
)
from tests.release.store import Snapshot, delta

SECRET = "CANARY-ATTR-4b83"


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("CREATE TABLE policies (id INTEGER PRIMARY KEY, name TEXT UNIQUE)")
    c.execute("CREATE TABLE runs (id INTEGER PRIMARY KEY, policy TEXT REFERENCES policies(name) ON UPDATE CASCADE)")
    yield c
    c.close()


def test_a_unique_column_has_two_physical_locations(conn):
    """The count a naive check gets wrong on a correct system.

    `policies.name` is UNIQUE, so its value exists in the table B-tree and in
    the unique index. Expecting one occurrence fails against working code.
    """
    locations = expected_locations(conn, ("policies", "name"))
    assert locations["policies"] == 1
    index = [k for k in locations if k != "policies"]
    assert index, f"the unique index was not counted: {locations}"
    assert sum(locations.values()) == 2


def test_an_observed_write_is_attributed_to_its_own_path(conn):
    before = Snapshot.take(conn)
    conn.execute("INSERT INTO policies(id, name) VALUES (1, ?)", (SECRET,))
    after = Snapshot.take(conn)

    paths = {a.path for a in attribute(conn, delta(before, after))}
    assert ("policies", "name") in paths


def test_the_index_copy_is_attributed_without_being_written_directly(conn):
    """Nothing wrote the index. The value is in it regardless."""
    before = Snapshot.take(conn)
    conn.execute("INSERT INTO policies(id, name) VALUES (1, ?)", (SECRET,))
    after = Snapshot.take(conn)

    attributions = attribute(conn, delta(before, after))
    copies = [a for a in attributions if a.basis == "copy" and a.path == ("policies", "name")]
    assert copies, "the unique index copy was not attributed"
    assert all(a.location != "policies" for a in copies)


def test_a_cascade_write_is_attributed_to_the_child_path(conn):
    """The write no statement names and no parent cell records.

    Updating `policies.name` rewrites `runs.policy` by ON UPDATE CASCADE. The
    parent's delta shows only the parent cell.
    """
    conn.execute("INSERT INTO policies(id, name) VALUES (1, 'before')")
    conn.execute("INSERT INTO runs(id, policy) VALUES (1, 'before')")

    before = Snapshot.take(conn)
    conn.execute("UPDATE policies SET name = ? WHERE id = 1", (SECRET,))
    after = Snapshot.take(conn)

    d = delta(before, after)
    attributions = attribute(conn, d)
    cascaded = [a for a in attributions if a.basis == "cascade"]

    assert ("runs", "policy") in {
        a.path for a in cascaded
    }, f"the cascade write was not attributed: {[str(a) for a in attributions]}"


def test_the_cascade_actually_happened(conn):
    """The premise behind the previous test.

    If the cascade did not fire, attributing it would be declaring a write
    that does not occur -- which is the failure mode this whole module exists
    to prevent.
    """
    conn.execute("INSERT INTO policies(id, name) VALUES (1, 'before')")
    conn.execute("INSERT INTO runs(id, policy) VALUES (1, 'before')")
    conn.execute("UPDATE policies SET name = ? WHERE id = 1", (SECRET,))

    assert conn.execute("SELECT policy FROM runs WHERE id = 1").fetchone()[0] == SECRET


def test_an_occurrence_no_path_explains_is_left_over(conn):
    """The failure that matters.

    A byte scan finds the value in a location the declared paths do not
    predict. That is an occurrence no rule was applied to.
    """
    before = Snapshot.take(conn)
    conn.execute("INSERT INTO policies(id, name) VALUES (1, ?)", (SECRET,))
    after = Snapshot.take(conn)

    attributions = attribute(conn, delta(before, after))
    physical = {"policies": 1, "sqlite_autoindex_policies_1": 1, "somewhere_else": 1}

    assert unexplained(physical, attributions) == {"somewhere_else": 1}


def test_predicted_occurrences_leave_nothing_over(conn):
    before = Snapshot.take(conn)
    conn.execute("INSERT INTO policies(id, name) VALUES (1, ?)", (SECRET,))
    after = Snapshot.take(conn)

    attributions = attribute(conn, delta(before, after))
    physical = {a.location: 0 for a in attributions}
    for a in attributions:
        physical[a.location] += 1

    assert unexplained(physical, attributions) == {}


def test_more_copies_than_predicted_is_reported(conn):
    """An extra copy in a predicted location is still unexplained."""
    before = Snapshot.take(conn)
    conn.execute("INSERT INTO policies(id, name) VALUES (1, ?)", (SECRET,))
    after = Snapshot.take(conn)

    attributions = attribute(conn, delta(before, after))
    predicted_here = sum(1 for a in attributions if a.location == "policies")
    # Deliberately far above the prediction. An earlier version used 3, which
    # happened to leave an excess of exactly 1 -- indistinguishable from a
    # presence flag, so a count-losing regression passed.
    physical = {"policies": predicted_here + 7}
    assert unexplained(physical, attributions) == {"policies": 7}


def test_a_path_with_no_copy_map_entry_is_an_error_not_a_zero(conn):
    """Fail closed. An unknown path predicting zero copies makes every
    occurrence of it unexplained-by-omission rather than by measurement."""
    with pytest.raises(Unattributed, match="policies.nonexistent"):
        expected_locations(conn, ("policies", "nonexistent"))


def test_cells_holding_reads_the_live_image_only(conn):
    """Attribution's observed source is a logical read.

    It cannot see a WAL frame or a freed page, and must not be asked to. Those
    occurrences belong to the corpus, and attributing one to a live path that
    no longer holds the value is how a historical occurrence gets excused.
    """
    conn.execute("INSERT INTO policies(id, name) VALUES (1, ?)", (SECRET,))
    assert ("policies", 1, "name") in cells_holding(conn, SECRET)

    conn.execute("DELETE FROM policies")
    assert cells_holding(conn, SECRET) == set(), "a logical read reported a value that is no longer live"


def test_a_column_indexed_twice_predicts_two_copies_in_that_index():
    """Copy COUNTS, not copy locations.

    `CREATE INDEX i ON t(c, c)` gives the column two key slots in one index,
    so its value exists twice there. Attributing one copy per location expects
    fewer occurrences than a permitted schema actually has, and the difference
    is reported as unexplained on a correct system.
    """
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, c TEXT)")
    conn.execute("CREATE INDEX i_twice ON t(c, c)")

    locations = expected_locations(conn, ("t", "c"))
    assert locations["i_twice"] == 2, f"the doubled key slot was not counted: {locations}"

    before = Snapshot.take(conn)
    conn.execute("INSERT INTO t(id, c) VALUES (1, ?)", (SECRET,))
    after = Snapshot.take(conn)

    attributions = attribute(conn, delta(before, after))
    # Filter by PATH. Counting every attribution in the index also counts
    # `t.id`, which is the rowid alias and therefore present in every index on
    # the table -- so the total was 3 and the doubled slot was invisible.
    in_index = [a for a in attributions if a.location == "i_twice" and a.path == ("t", "c")]
    assert len(in_index) == 2, f"predicted {len(in_index)} copies of t.c in i_twice, schema has 2"

    alias = [a for a in attributions if a.location == "i_twice" and a.path == ("t", "id")]
    assert len(alias) == 1, "the rowid alias should be attributed once per index"
    conn.close()


def test_cells_holding_finds_a_value_stored_as_a_blob():
    """A logical read still has to cope with every storage class."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, c BLOB)")
    conn.execute("INSERT INTO t(id, c) VALUES (1, ?)", (SECRET.encode(),))

    stored = conn.execute("SELECT c FROM t").fetchone()[0]
    assert isinstance(stored, bytes), "premise changed: no longer stored as a BLOB"
    assert ("t", 1, "c") in cells_holding(conn, SECRET)
    conn.close()


def test_cells_holding_finds_a_non_ascii_value_stored_as_a_blob():
    """The bytes branch, not the str() fallback.

    `str(b'caf\\xc3\\xa9')` shows escaped hex, so the value's own characters are
    absent from the string being searched.
    """
    secret = "CANARY-café-2a71"
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, c BLOB)")
    conn.execute("INSERT INTO t(id, c) VALUES (1, ?)", (secret.encode(),))

    stored = conn.execute("SELECT c FROM t").fetchone()[0]
    assert secret not in str(stored), "premise changed: the repr fallback would find this"
    assert ("t", 1, "c") in cells_holding(conn, secret)
    conn.close()
