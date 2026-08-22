"""Both directions of declared-versus-produced, and the delta that feeds them."""

from __future__ import annotations

import sqlite3

import pytest

from tests.release.store import Snapshot, compare, delta


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE policy (id INTEGER PRIMARY KEY, name TEXT, note TEXT)")
    c.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY, detail TEXT)")
    yield c
    c.close()


def test_delta_addresses_new_cells_by_table_rowid_column(conn):
    before = Snapshot.take(conn)
    conn.execute("INSERT INTO policy(id, name, note) VALUES (1, 'n', 'x')")
    after = Snapshot.take(conn)

    d = delta(before, after)
    assert ("policy", 1, "name") in d.added
    assert d.added[("policy", 1, "name")] == "n"
    assert not d.removed and not d.changed


def test_delta_reports_an_updated_cell_as_changed_not_added(conn):
    conn.execute("INSERT INTO policy(id, name) VALUES (1, 'before')")
    before = Snapshot.take(conn)
    conn.execute("UPDATE policy SET name = 'after' WHERE id = 1")
    after = Snapshot.take(conn)

    d = delta(before, after)
    assert d.changed[("policy", 1, "name")] == ("before", "after")
    assert not d.added


def test_a_changed_cell_counts_as_produced(conn):
    """An overwrite writes the value to disk as surely as an insert does."""
    conn.execute("INSERT INTO policy(id, name) VALUES (1, 'before')")
    before = Snapshot.take(conn)
    conn.execute("UPDATE policy SET name = 'SECRET' WHERE id = 1")
    after = Snapshot.take(conn)

    assert ("policy", 1, "name") in delta(before, after).produced


def test_a_produced_cell_that_was_not_declared_fails(conn):
    """The write nobody wrote down."""
    before = Snapshot.take(conn)
    conn.execute("INSERT INTO policy(id, name, note) VALUES (1, 'n', 'undeclared')")
    after = Snapshot.take(conn)

    declared = {("policy", 1, "name"), ("policy", 1, "id")}
    problems = compare(delta(before, after).produced, declared)

    assert [str(p) for p in problems] == ["produced-not-declared: policy.note (rowid 1)"]


def test_a_declared_cell_that_was_not_produced_fails(conn):
    """The stale declaration.

    This is the direction that a one-sided check misses: the exercise stopped
    writing the row, the declaration stayed behind, and every count over it
    read zero and agreed with itself.
    """
    before = Snapshot.take(conn)
    conn.execute("INSERT INTO policy(id, name) VALUES (1, 'n')")
    after = Snapshot.take(conn)

    declared = {
        ("policy", 1, "id"),
        ("policy", 1, "name"),
        ("policy", 1, "note"),
        ("audit", 1, "detail"),  # nothing writes audit any more
    }
    problems = compare(delta(before, after).produced, declared)
    directions = {p.direction for p in problems}

    assert directions == {"declared-not-produced"}
    assert "declared-not-produced: audit.detail (rowid 1)" in [str(p) for p in problems]


def test_agreement_is_the_only_empty_result(conn):
    before = Snapshot.take(conn)
    conn.execute("INSERT INTO policy(id, name, note) VALUES (1, 'n', 'x')")
    after = Snapshot.take(conn)

    exact = {("policy", 1, "id"), ("policy", 1, "name"), ("policy", 1, "note")}
    assert compare(delta(before, after).produced, exact) == []


def test_the_snapshot_covers_generated_columns(conn):
    """table_info hides them; a value written into one is still on disk."""
    conn.execute("CREATE TABLE g (id INTEGER PRIMARY KEY, v TEXT, u TEXT GENERATED ALWAYS AS (upper(v)) STORED)")
    conn.execute("INSERT INTO g(id, v) VALUES (1, 'secret')")

    cells = Snapshot.take(conn).cells
    assert cells[("g", 1, "u")] == "SECRET", "a stored generated column was not snapshotted"


def test_the_snapshot_covers_every_live_table_without_being_told_them(conn):
    conn.execute("INSERT INTO policy(id, name) VALUES (1, 'p')")
    conn.execute("INSERT INTO audit(id, detail) VALUES (1, 'a')")

    tables = {t for (t, _, _) in Snapshot.take(conn).cells}
    assert tables == {"policy", "audit"}
