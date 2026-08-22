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


def test_ten_relationships_of_which_six_write(conn):
    """The count is stated because 'exactly the six' was ambiguous.

    RESTRICT and NO ACTION are inside the pin and outside the cascade map:
    pinned because a change to one is schema drift worth failing on, excluded
    because neither can carry a value into another table.
    """
    observed = referential_actions(conn)
    assert len(observed) == 10
    assert len([a for a in observed if a[3] in WRITING_ACTIONS]) == 6


def test_the_cascade_map_covers_exactly_the_writing_actions(conn):
    mapped = {(child, col, act) for entries in cascade_map(conn).values() for child, col, act in entries}
    assert mapped == {(t, c, a) for t, c, _p, a in REFERENTIAL_ACTIONS if a in WRITING_ACTIONS}
    assert all(action in WRITING_ACTIONS for _, _, action in mapped)


def test_deleting_a_policy_is_mapped_to_its_cascading_children(conn):
    assert ("rule_sets", "policy_id", "CASCADE") in cascade_map(conn)["policies"]
    assert ("api_keys", "policy_id", "SET NULL") in cascade_map(conn)["policies"]


def test_the_copy_map_finds_the_unique_index_holding_a_policy_name(conn):
    """One logical row, two byte copies.

    `Policy.name` is unique, so SQLite keeps the value in
    `sqlite_autoindex_policies_2` as well as in the table. A byte count that
    did not know this would read the second copy as an extra occurrence.
    """
    locations = copy_map(conn)[("policies", "name")]
    assert "policies" in locations
    assert "sqlite_autoindex_policies_2" in locations, sorted(locations)


def test_the_copy_map_covers_every_column(conn):
    mapping = copy_map(conn)
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for table in tables:
        for column in (r[1] for r in conn.execute(f"PRAGMA table_info('{table}')")):
            assert (table, column) in mapping, f"{table}.{column} has no declared location"
            assert table in mapping[(table, column)]


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
