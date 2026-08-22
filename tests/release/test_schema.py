"""The schema invariant, the copy map, and the cascade map.

Every assertion here is mutation-tested against a throwaway database. An
invariant nobody has broken is an invariant nobody has checked.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from tests.release.schema import (
    REFERENTIAL_ACTIONS,
    WRITING_ACTIONS,
    cascade_map,
    copy_map,
    invariant,
    referential_actions,
)

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def head_db(tmp_path_factory) -> Path:
    """A database migrated through the real Alembic chain to head."""
    path = tmp_path_factory.mktemp("release-schema") / "head.db"
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO,
        env={**os.environ, "DB_URL": f"sqlite:///{path}"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return path


@pytest.fixture
def conn(head_db: Path):
    connection = sqlite3.connect(head_db)
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def scratch_path(head_db: Path, tmp_path: Path) -> Path:
    """A writable copy, so a mutation never touches the shared head database."""
    copy = tmp_path / "scratch.db"
    copy.write_bytes(head_db.read_bytes())
    return copy


@pytest.fixture
def scratch(scratch_path: Path):
    connection = sqlite3.connect(scratch_path)
    try:
        yield connection
    finally:
        connection.close()


def test_the_head_schema_satisfies_the_invariant(conn):
    assert invariant(conn) == []


def test_every_referential_action_is_pinned(conn):
    assert referential_actions(conn) == set(REFERENTIAL_ACTIONS)


def test_ten_relationships_of_which_six_write_on_delete(conn):
    """The count is stated because 'exactly the six' was ambiguous.

    RESTRICT and NO ACTION are inside the pin and outside the cascade map:
    pinned because a change to one is schema drift worth failing on, excluded
    because neither modifies a child value.
    """
    observed = referential_actions(conn)
    assert len(observed) == 10
    assert len([a for a in observed if a[5] in WRITING_ACTIONS]) == 6


def test_on_update_is_pinned_too(conn):
    """Every ON UPDATE is NO ACTION today -- which is why omitting it was invisible.

    An `ON UPDATE CASCADE` copies the parent's new value into the child, a
    different-target write the statement never names. The first version read
    only `on_delete` and would have missed every one. Pinning the current
    values means introducing one is a build failure rather than a silent hole.
    """
    assert {a[4] for a in referential_actions(conn)} == {"NO ACTION"}


def test_an_added_on_update_cascade_is_refused(scratch_path: Path):
    mutate = sqlite3.connect(scratch_path)
    try:
        mutate.executescript(
            """
            PRAGMA writable_schema=ON;
            UPDATE sqlite_master
               SET sql = replace(sql, 'ON DELETE CASCADE', 'ON UPDATE CASCADE ON DELETE CASCADE')
             WHERE type='table' AND name='rule_sets';
            PRAGMA writable_schema=OFF;
            """
        )
        mutate.commit()
    finally:
        mutate.close()
    reopened = sqlite3.connect(scratch_path)
    try:
        kinds = _kinds(reopened)
        assert "referential-action-added" in kinds, invariant(reopened)
    finally:
        reopened.close()


def test_the_cascade_map_covers_exactly_the_writing_actions(conn):
    mapped = {e for entries in cascade_map(conn).values() for e in entries}
    expected = {(t, c, "DELETE", d) for t, c, _p, _pc, _u, d in REFERENTIAL_ACTIONS if d in WRITING_ACTIONS} | {
        (t, c, "UPDATE", u) for t, c, _p, _pc, u, _d in REFERENTIAL_ACTIONS if u in WRITING_ACTIONS
    }
    assert mapped == expected
    assert all(action in WRITING_ACTIONS for _, _, _, action in mapped)


def test_deleting_a_policy_is_mapped_to_its_cascading_children(conn):
    by_policy_id = cascade_map(conn)[("policies", "id")]
    assert ("rule_sets", "policy_id", "DELETE", "CASCADE") in by_policy_id
    assert ("api_keys", "policy_id", "DELETE", "SET NULL") in by_policy_id


def test_the_copy_map_finds_the_unique_index_holding_a_policy_name(conn):
    """One logical row, two byte copies.

    `Policy.name` is unique, so SQLite keeps the value in
    `sqlite_autoindex_policies_2` as well as in the table. A byte count that
    did not know this would read the second copy as an extra occurrence.
    """
    locations = copy_map(conn)[("policies", "name")]
    assert locations["policies"] == 1
    assert locations["sqlite_autoindex_policies_2"] == 1, dict(locations)
    assert sum(locations.values()) == 2, "one logical row, two byte copies"


def test_the_copy_map_covers_every_column(conn):
    mapping = copy_map(conn)
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for table in tables:
        for column in (r[1] for r in conn.execute(f"PRAGMA table_info('{table}')")):
            assert (table, column) in mapping, f"{table}.{column} has no declared location"
            assert mapping[(table, column)][table] == 1


# --- mutations: each must be caught by its own assertion ------------------
#
# Applied to a scratch copy, never to a migration, so a failure here cannot
# corrupt the fixture the other tests share.


def _kinds(connection) -> set[str]:
    return {v.kind for v in invariant(connection)}


def test_a_trigger_is_refused(scratch):
    scratch.execute("CREATE TRIGGER t AFTER INSERT ON policies BEGIN UPDATE policies SET name=name; END")
    assert "trigger" in _kinds(scratch)


def test_a_view_is_refused(scratch):
    scratch.execute("CREATE VIEW v AS SELECT name FROM policies")
    assert "view" in _kinds(scratch)


def test_a_changed_referential_action_is_refused(scratch_path: Path):
    """Rewriting the stored schema, then reopening.

    A referential action is part of the CREATE TABLE text, so it cannot be
    altered in place -- the mutation edits sqlite_master directly and the
    database is reopened so SQLite re-parses it.
    """
    mutate = sqlite3.connect(scratch_path)
    try:
        mutate.executescript(
            """
            PRAGMA writable_schema=ON;
            UPDATE sqlite_master
               SET sql = replace(sql, 'ON DELETE CASCADE', 'ON DELETE NO ACTION')
             WHERE type='table' AND name='rule_sets';
            PRAGMA writable_schema=OFF;
            """
        )
        mutate.commit()
    finally:
        mutate.close()

    reopened = sqlite3.connect(scratch_path)
    try:
        kinds = _kinds(reopened)
        assert (
            "referential-action-added" in kinds or "referential-action-removed" in kinds
        ), f"the changed action was not detected: {invariant(reopened)}"
    finally:
        reopened.close()


def test_a_generated_column_is_refused(scratch):
    scratch.execute("ALTER TABLE policies ADD COLUMN shadow_name TEXT GENERATED ALWAYS AS (name) STORED")
    assert "generated-column" in _kinds(scratch)


def test_a_virtual_table_is_refused(scratch):
    scratch.execute("CREATE VIRTUAL TABLE docs USING fts5(body)")
    kinds = _kinds(scratch)
    assert "virtual" in kinds
    assert "shadow" in kinds, "the module's shadow tables must be refused too"


def test_an_expression_index_is_refused(scratch):
    scratch.execute("CREATE INDEX e_expr ON policies(CAST(name AS TEXT))")
    assert "expression-index" in _kinds(scratch)


def test_a_partial_index_is_refused(scratch):
    scratch.execute("CREATE INDEX e_partial ON policies(name) WHERE report_only = 1")
    assert "partial-index" in _kinds(scratch)


def test_a_without_rowid_table_is_refused(scratch):
    scratch.execute("CREATE TABLE wr (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID")
    assert "without-rowid" in _kinds(scratch)


# --- the forms round 1 showed were evadable ------------------------------


def test_a_partial_index_written_across_lines_is_refused(scratch):
    """Structural flag, not token matching.

    `CREATE INDEX ... ON t(c)\nWHERE ...` is legal and evaded a `" where "`
    substring rule entirely, while a non-partial index named
    "plain where marker" was wrongly flagged by it.
    """
    scratch.execute("CREATE INDEX partial_newline ON policies(name)\nWHERE report_only = 1")
    assert "partial-index" in _kinds(scratch)


def test_an_index_whose_name_contains_where_is_not_flagged(scratch):
    scratch.execute('CREATE INDEX "plain where marker" ON policies(name)')
    assert "partial-index" not in _kinds(scratch)


def test_a_without_rowid_table_written_across_lines_is_refused(scratch):
    scratch.execute("CREATE TABLE wr_newline (k TEXT PRIMARY KEY, v TEXT) WITHOUT\nROWID")
    assert "without-rowid" in _kinds(scratch)


def test_a_column_named_without_rowid_is_not_flagged(scratch):
    scratch.execute('CREATE TABLE ordinary (id INTEGER PRIMARY KEY, "without rowid" TEXT)')
    assert "without-rowid" not in _kinds(scratch)


def test_a_temp_trigger_writing_the_main_schema_is_refused(scratch):
    """Connection-local, invisible to sqlite_master, and still a writer.

    A TEMP trigger can be attached to a main-schema table and write another
    main-schema table. Checking only sqlite_master reported nothing while the
    value was copied to a different target.
    """
    scratch.execute("CREATE TABLE temp_trigger_source (v TEXT)")
    scratch.execute("CREATE TABLE temp_trigger_sink (v TEXT)")
    scratch.execute(
        "CREATE TEMP TRIGGER t_copy AFTER INSERT ON temp_trigger_source "
        "BEGIN INSERT INTO temp_trigger_sink(v) VALUES (NEW.v); END"
    )
    assert "temp-trigger" in _kinds(scratch)

    # And it really does write the other target.
    scratch.execute("INSERT INTO temp_trigger_source(v) VALUES ('CANARY')")
    assert scratch.execute("SELECT v FROM temp_trigger_sink").fetchall() == [("CANARY",)]


def test_a_temp_view_is_refused(scratch):
    scratch.execute("CREATE TEMP VIEW tv AS SELECT name FROM policies")
    assert "temp-view" in _kinds(scratch)


def test_a_repeated_index_term_is_counted_twice(scratch):
    """A set of B-tree names is not an occurrence-count oracle.

    `CREATE INDEX i ON t(c, c)` gives `c` two key slots in one index, so the
    value exists three times in a vacuumed database -- once in the table, twice
    in the index -- while a set reports two locations.
    """
    scratch.execute("CREATE TABLE duplicate_terms (c TEXT)")
    scratch.execute("CREATE INDEX duplicate_terms_i ON duplicate_terms(c, c)")
    locations = copy_map(scratch)[("duplicate_terms", "c")]
    assert locations["duplicate_terms_i"] == 2, dict(locations)
    assert sum(locations.values()) == 3, dict(locations)


# --- the guard on the guard -----------------------------------------------
#
# Round 1 found that "removing any one detector stops its mutation being
# caught" was false for one of eight: with the virtual/shadow detector removed,
# an FTS5 table is STILL refused, because its shadow tables are WITHOUT ROWID.
# The mutation is caught -- by a different detector.
#
# That claim lived only in a commit message, where nothing could contradict it.
# It lives here now, stated as what is actually true.


def _violations_with_detector_removed(scratch, removed_kinds: set[str]):
    """What `invariant` would report if the named detectors did not exist."""
    return [v for v in invariant(scratch) if v.kind not in removed_kinds]


def test_the_virtual_detector_is_the_only_one_catching_an_fts_table(scratch):
    """Round 1 found an overlap here; the structural fix removed it.

    Under the old `"without rowid" in sql` rule an FTS5 table was ALSO refused
    as without-rowid, because that substring appears in its shadow tables'
    DDL. So removing the virtual/shadow detector left the mutation still
    caught, and "removing any one detector stops its mutation being caught"
    was false for that one of eight.

    Replacing the substring with `table_list.wr` scoped to `type == "table"`
    changed that: shadow tables have type `shadow`, so the without-rowid rule
    no longer sees them, and the virtual/shadow detector is now genuinely the
    only thing refusing an FTS table.

    Recorded because it would be easy to write round 1's observation down as a
    standing fact after the fix had already invalidated it.
    """
    scratch.execute("CREATE VIRTUAL TABLE docs USING fts5(body)")
    kinds = _kinds(scratch)
    assert "virtual" in kinds and "shadow" in kinds

    assert (
        _violations_with_detector_removed(scratch, {"virtual", "shadow"}) == []
    ), "another detector is also catching the FTS table; the overlap round 1 found has returned"


@pytest.mark.parametrize(
    "kind,make",
    [
        ("trigger", "CREATE TRIGGER t AFTER INSERT ON policies BEGIN UPDATE policies SET name=name; END"),
        ("view", "CREATE VIEW v AS SELECT name FROM policies"),
        (
            "generated-column",
            "ALTER TABLE policies ADD COLUMN shadow_name TEXT GENERATED ALWAYS AS (name) STORED",
        ),
        ("expression-index", "CREATE INDEX e_expr ON policies(CAST(name AS TEXT))"),
        ("partial-index", "CREATE INDEX e_partial ON policies(name) WHERE report_only = 1"),
        ("without-rowid", "CREATE TABLE wr (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID"),
    ],
)
def test_each_remaining_detector_is_the_only_one_catching_its_mutation(scratch, kind, make):
    """The direction that matters: no OTHER detector is doing this one's work.

    Without this, a detector could be dead code while its mutation stayed
    caught by a neighbour -- which is exactly what the virtual/shadow case
    turned out to be.
    """
    scratch.execute(make)
    assert kind in _kinds(scratch)
    assert _violations_with_detector_removed(scratch, {kind}) == [], (
        f"{kind}'s mutation is also caught by another detector: "
        f"{[(v.kind, v.detail) for v in _violations_with_detector_removed(scratch, {kind})]}"
    )


# --- the rowid alias, pinned and bounded ----------------------------------


def test_the_rowid_alias_copies_are_pinned_at_head(conn):
    """Deleting the alias block left all 31 tests green.

    The repair was correct and unbound: nothing exercised an INTEGER PRIMARY
    KEY with secondary indexes, so it could regress silently. These are the
    measured head counts.
    """
    mapping = copy_map(conn)
    assert sum(mapping[("interactions", "id")].values()) == 6, dict(mapping[("interactions", "id")])
    assert sum(mapping[("interaction_contents", "id")].values()) == 5
    assert sum(mapping[("content_access_audit", "id")].values()) == 5
    assert sum(mapping[("policies", "name")].values()) == 2


def test_a_composite_primary_key_column_is_not_treated_as_a_rowid_alias(scratch):
    """`table_info.pk` is an ordinal, not a flag.

    In `PRIMARY KEY(a, b)` the column `a` also reports pk == 1. Treating it as
    a rowid alias put its value in indexes that never carry it and counted the
    composite autoindex twice -- and the invariant permits this schema, so
    Task 4's canonical count would have been wrong with nothing failing.
    """
    scratch.execute("CREATE TABLE composite (a INTEGER, b TEXT, PRIMARY KEY(a, b))")
    scratch.execute("CREATE INDEX composite_b ON composite(b)")
    assert invariant(scratch) == [], "the invariant permits this table"

    locations = copy_map(scratch)[("composite", "a")]
    assert "composite_b" not in locations, dict(locations)
    assert locations["composite"] == 1


def test_a_genuine_single_column_alias_is_still_recognised(scratch):
    scratch.execute("CREATE TABLE aliased (id INTEGER PRIMARY KEY, v TEXT)")
    scratch.execute("CREATE INDEX aliased_v ON aliased(v)")
    locations = copy_map(scratch)[("aliased", "id")]
    assert locations["aliased_v"] == 1, dict(locations)
