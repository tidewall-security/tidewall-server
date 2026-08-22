"""The trace is not a value ledger; the boundary read is the assertion."""

from __future__ import annotations

import sqlite3

import pytest

from tests.release.trace import TracedConnection, UnreadableForbiddenColumn

SECRET = "CANARY-TRACE-8e14"


@pytest.fixture
def traced():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE src (v TEXT)")
    conn.execute("CREATE TABLE audit (v TEXT)")
    t = TracedConnection(conn=conn, forbidden=frozenset({("audit", "v")}), watched=(SECRET,))
    yield t
    conn.close()


def test_a_bound_parameter_does_appear_in_the_trace(traced):
    """Which is what makes the trace look sufficient."""
    traced.execute("INSERT INTO src(v) VALUES (?)", (SECRET,))
    assert traced.trace_mentions(SECRET), "the expanded trace should show it"


def test_a_sql_computed_write_never_appears_in_the_trace(traced):
    """The structural gap.

    The value reaches a forbidden column, and no statement text contains it.
    A check built on the trace passes here, and is wrong.
    """
    traced.execute("INSERT INTO src(v) VALUES (?)", (SECRET,))
    traced.execute("INSERT INTO audit(v) SELECT v FROM src")

    computed = [s for s in traced.statements if "INSERT INTO audit" in s.sql]
    assert computed, "the copying statement was not traced at all"
    assert not any(s.mentions(SECRET) for s in computed), (
        "premise changed: the copying statement now carries the value, so this "
        "no longer demonstrates the gap the boundary read exists for"
    )


def test_the_boundary_read_catches_the_write_the_trace_cannot_see(traced):
    """Same exercise, real assertion."""
    traced.execute("INSERT INTO src(v) VALUES (?)", (SECRET,))
    traced.execute("INSERT INTO audit(v) SELECT v FROM src")

    assert traced.violations, "the forbidden column read reported nothing"
    v = traced.violations[0]
    assert (v.table, v.column) == ("audit", "v")
    assert "INSERT INTO audit" in v.after_statement


def test_a_trigger_written_value_is_caught(traced):
    """The trigger gap is the DESTINATION, not the value.

    The value is plainly in the trace -- the `src` insert carries it as a bound
    parameter. What no statement shows is that it also came to rest in `audit`.
    A reviewer reading this trace sees a write to a permitted table and has no
    reason to look further.
    """
    traced.conn.execute("CREATE TRIGGER copy_it AFTER INSERT ON src BEGIN " "INSERT INTO audit(v) VALUES (NEW.v); END")
    traced.execute("INSERT INTO src(v) VALUES (?)", (SECRET,))

    assert traced.violations, "a trigger-written value escaped the boundary read"
    assert traced.conn.execute("SELECT count(*) FROM audit").fetchone()[0] == 1

    # Every statement that carries the value names only `src`. Nothing in the
    # trace attributes the value to `audit`, which is where it actually landed.
    carrying = traced.trace_mentions(SECRET)
    assert carrying, "premise changed: the value is no longer in the trace at all"
    assert all(
        "audit" not in st.sql for st in carrying
    ), "premise changed: a value-carrying statement now names the destination"


def test_a_default_written_value_is_caught():
    """Nothing in the statement, nothing in the parameters."""
    conn = sqlite3.connect(":memory:")
    conn.execute(f"CREATE TABLE audit (id INTEGER PRIMARY KEY, v TEXT DEFAULT '{SECRET}')")
    t = TracedConnection(conn=conn, forbidden=frozenset({("audit", "v")}), watched=(SECRET,))
    t.execute("INSERT INTO audit(id) VALUES (1)")

    assert t.violations
    assert not t.trace_mentions(SECRET)
    conn.close()


def test_a_clean_run_reports_no_violation(traced):
    """The check has to be able to pass, or its failures mean nothing."""
    traced.execute("INSERT INTO src(v) VALUES (?)", (SECRET,))
    traced.execute("INSERT INTO audit(v) VALUES ('unrelated')")
    assert traced.violations == []


def test_every_statement_boundary_is_read_not_only_the_last(traced):
    """A sweep that only runs at the end attributes the violation to the wrong
    statement, and misses a value that is written and then removed."""
    traced.execute("INSERT INTO audit(v) VALUES (?)", (SECRET,))
    traced.execute("DELETE FROM audit")

    assert traced.violations, "the value was written and removed between boundaries"
    assert "INSERT INTO audit" in traced.violations[0].after_statement
    assert traced.conn.execute("SELECT count(*) FROM audit").fetchone()[0] == 0


def test_a_secret_stored_as_a_blob_is_caught():
    """A secret on disk is a secret whatever its storage class.

    Comparing only `str` column values let a CAST-to-BLOB write pass.
    """
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY, v BLOB)")
    t = TracedConnection(conn=conn, forbidden=frozenset({("audit", "v")}), watched=(SECRET,))
    t.execute("INSERT INTO audit(id, v) VALUES (1, CAST(? AS BLOB))", (SECRET,))

    assert t.violations, "a BLOB-stored secret was not read as a violation"
    assert isinstance(
        conn.execute("SELECT v FROM audit").fetchone()[0], bytes
    ), "premise changed: the value is no longer stored as a BLOB"
    conn.close()


def test_a_secret_embedded_in_a_larger_blob_is_caught():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY, v BLOB)")
    t = TracedConnection(conn=conn, forbidden=frozenset({("audit", "v")}), watched=(SECRET,))
    t.execute("INSERT INTO audit(id, v) VALUES (1, ?)", (b"prefix" + SECRET.encode() + b"suffix",))
    assert t.violations
    conn.close()


def test_every_declared_forbidden_pair_is_swept_not_just_the_first():
    """Two pairs, and the violation is in the second."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE a_first (id INTEGER PRIMARY KEY, v TEXT)")
    conn.execute("CREATE TABLE z_second (id INTEGER PRIMARY KEY, v TEXT)")
    t = TracedConnection(
        conn=conn,
        forbidden=frozenset({("a_first", "v"), ("z_second", "v")}),
        watched=(SECRET,),
    )
    t.execute("INSERT INTO z_second(id, v) VALUES (1, ?)", (SECRET,))

    assert t.violations, "the second declared pair was never swept"
    assert t.violations[0].table == "z_second"
    conn.close()


def test_a_misspelled_forbidden_column_is_an_error_not_a_skip():
    """The check that silently never ran.

    Swallowing every OperationalError meant a typo in a declaration produced a
    check which passed for the whole run without reading anything.
    """
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY, v TEXT)")
    t = TracedConnection(conn=conn, forbidden=frozenset({("audit", "vv")}), watched=(SECRET,))
    with pytest.raises(UnreadableForbiddenColumn, match="audit.vv"):
        t.execute("INSERT INTO audit(id, v) VALUES (1, 'x')")
    conn.close()


def test_a_forbidden_pair_whose_table_never_exists_fails_at_the_end():
    """Tolerated during the run, refused at the close.

    A boundary before the schema exists has nothing to read. A whole run with
    nothing to read is a declaration with nothing behind it.
    """
    conn = sqlite3.connect(":memory:")
    t = TracedConnection(conn=conn, forbidden=frozenset({("never_made", "v")}), watched=(SECRET,))
    t.execute("CREATE TABLE other (v TEXT)")  # tolerated: no such table yet

    with pytest.raises(UnreadableForbiddenColumn, match="never_made.v"):
        t.verify_every_pair_was_read()
    conn.close()


def test_verify_passes_when_every_pair_was_actually_read(traced):
    traced.execute("INSERT INTO src(v) VALUES ('ok')")
    traced.verify_every_pair_was_read()
