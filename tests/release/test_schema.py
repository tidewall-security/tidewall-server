"""The schema invariant, the copy map, and the cascade map.

Every assertion here is mutation-tested against a throwaway database. An
invariant nobody has broken is an invariant nobody has checked.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from contextlib import closing
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
    # A Counter now: a duplicate constraint with identical child column,
    # parent column and actions collapses in a set, so an eleventh
    # database-side writer could arrive with the count assertion green.
    observed = referential_actions(conn)
    assert set(observed) == set(REFERENTIAL_ACTIONS)
    assert all(count == 1 for count in observed.values()), observed


def test_thirty_relationships_of_which_twenty_one_write_on_delete(conn):
    # Composite constraints count once, even when multiple columns carry scope.
    observed = referential_actions(conn)
    assert sum(observed.values()) == 30
    assert sum(count for fk, count in observed.items() if fk[5] in WRITING_ACTIONS) == 21


def test_native_index_slots_and_physical_session_token_copies(scratch):
    locations = copy_map(scratch).locations(("agent_sessions", "native_session_token"))
    assert locations == {"agent_sessions": 1, "sqlite_autoindex_agent_sessions_2": 1, "uq_native_session_scope": 1}
    assert copy_map(scratch).locations(("native_prompt_deliveries", "decision_id")) == {
        "native_prompt_deliveries": 1,
        "ix_native_prompt_deliveries_decision_id": 1,
    }
    scratch.execute("CREATE INDEX unexpected_token_copy ON native_prompt_grants(session_token)")
    assert any(v.kind == "native-index-slots" and v.detail == "native_prompt_grants" for v in invariant(scratch))


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
    expected = {
        (parent, pc, table, col, event, action)
        for table, columns, parent, parent_columns, on_update, on_delete in REFERENTIAL_ACTIONS
        for col, pc in zip(columns, parent_columns, strict=True)
        for event, action in (("UPDATE", on_update), ("DELETE", on_delete))
        if action in WRITING_ACTIONS
    }
    mapped = {(*parent, *child) for parent, children in cascade_map(conn).items() for child in children}
    assert mapped == expected


def test_deleting_a_policy_is_mapped_to_its_cascading_children(conn):
    """The map holds what a policy deletion WRITES, and api_keys is no longer
    among them.

    It used to be there with SET NULL, which is a write: deleting a policy
    reached into every key bound to it and blanked the binding. api_keys is
    RESTRICT now, so the deletion is refused instead and nothing is touched --
    which is why it belongs outside this map rather than inside it with a
    different action.
    """
    by_policy_id = cascade_map(conn)[("policies", "id")]
    assert ("rule_sets", "policy_id", "DELETE", "CASCADE") in by_policy_id
    assert not any(child == "api_keys" for child, *_ in by_policy_id), sorted(by_policy_id)


def test_the_copy_map_finds_the_unique_index_holding_a_policy_name(conn):
    """One logical row, two byte copies.

    `Policy.name` is unique, so SQLite keeps the value in
    `sqlite_autoindex_policies_2` as well as in the table. A byte count that
    did not know this would read the second copy as an extra occurrence.
    """
    locations = copy_map(conn).locations(("policies", "name"))
    assert locations["policies"] == 1
    assert locations["sqlite_autoindex_policies_2"] == 1, dict(locations)
    assert sum(locations.values()) == 2, "one logical row, two byte copies"


def test_the_copy_map_covers_every_column(conn):
    mapping = copy_map(conn)
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for table in tables:
        for column in (r[1] for r in conn.execute(f"PRAGMA table_info('{table}')")):
            assert (table, column) in mapping.slots, f"{table}.{column} has no declared location"
            assert mapping.slots[(table, column)][table] == 1


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
    locations = copy_map(scratch).locations(("duplicate_terms", "c"))
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
    assert sum(mapping.locations(("interactions", "id")).values()) == 6, dict(mapping.locations(("interactions", "id")))
    assert sum(mapping.locations(("interaction_contents", "id")).values()) == 5
    assert sum(mapping.locations(("content_access_audit", "id")).values()) == 5
    assert sum(mapping.locations(("policies", "name")).values()) == 2


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

    locations = copy_map(scratch).locations(("composite", "a"))
    assert "composite_b" not in locations, dict(locations)
    assert locations["composite"] == 1


def test_a_genuine_single_column_alias_is_still_recognised(scratch):
    scratch.execute("CREATE TABLE aliased (id INTEGER PRIMARY KEY, v TEXT)")
    scratch.execute("CREATE INDEX aliased_v ON aliased(v)")
    locations = copy_map(scratch).locations(("aliased", "id"))
    assert locations["aliased_v"] == 1, dict(locations)


def test_an_integer_primary_key_desc_is_not_a_rowid_alias(scratch):
    """SQLite's DESC exception.

    `INTEGER PRIMARY KEY DESC` is not a rowid alias: rowid and the column hold
    different values, so the column is absent from secondary indexes. Counting
    it as an alias false-fails the canonical byte cardinality on a schema the
    invariant permits.
    """
    scratch.execute("CREATE TABLE desc_pk (id INTEGER PRIMARY KEY DESC, v TEXT)")
    scratch.execute("CREATE INDEX desc_pk_v ON desc_pk(v)")
    scratch.execute("INSERT INTO desc_pk(id, v) VALUES (123, 'x')")
    assert invariant(scratch) == [], "the invariant permits this table"
    assert scratch.execute("SELECT rowid, id FROM desc_pk").fetchone() == (1, 123)

    locations = copy_map(scratch).locations(("desc_pk", "id"))
    assert "desc_pk_v" not in locations, dict(locations)
    assert locations["desc_pk"] == 1


def test_a_desc_primary_key_with_a_comment_is_not_a_rowid_alias(scratch):
    """The lexical rule missed this; the structural one cannot.

    A legal SQL comment between `INTEGER` and `PRIMARY KEY DESC` evaded a
    token-layout regex. SQLite's own metadata answers directly: a genuine alias
    has no pk-origin autoindex, and every other primary key has one.
    """
    scratch.execute("CREATE TABLE desc_comment (id INTEGER /* accepted SQL comment */ PRIMARY KEY DESC, v TEXT)")
    scratch.execute("CREATE INDEX desc_comment_v ON desc_comment(v)")
    scratch.execute("INSERT INTO desc_comment(id, v) VALUES (123, 'x')")
    assert invariant(scratch) == [], "the invariant permits this table"
    assert scratch.execute("SELECT rowid, id FROM desc_comment").fetchone() == (1, 123)

    locations = copy_map(scratch).locations(("desc_comment", "id"))
    assert "desc_comment_v" not in locations, dict(locations)
    assert locations["sqlite_autoindex_desc_comment_1"] == 1, dict(locations)


def test_an_unknown_object_type_is_refused_unexamined(scratch):
    """Allowlisted, not blocklisted.

    Refusing only the `virtual` and `shadow` values known today meant a SQLite
    version introducing a sixth object type would pass silently, while the
    module claimed a new class becomes a build failure. A thin proxy stands in
    for that future type, since sqlite3.Connection.execute cannot be patched.
    """

    class _FutureType:
        def __init__(self, real):
            self._real = real

        def execute(self, sql, *args, **kwargs):
            if sql.strip() == "PRAGMA table_list":
                return [("main", "surprise", "some_future_type", 2, 0, 0)]
            return self._real.execute(sql, *args, **kwargs)

    kinds = {v.kind for v in invariant(_FutureType(scratch))}
    assert "unknown-object-type" in kinds, kinds


def test_a_duplicate_foreign_key_constraint_is_detected(scratch_path):
    """Multiplicity, not membership.

    Two distinct constraints with the same child column, parent column and
    actions are one tuple in a set, so a duplicated relationship -- an eleventh
    database-side writer -- passed a test named for counting ten.
    """
    mutate = sqlite3.connect(scratch_path)
    try:
        row = mutate.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='rule_sets'").fetchone()
        original = row[0]
        needle = next(
            (line.strip().rstrip(",") for line in original.splitlines() if "FOREIGN KEY" in line),
            None,
        )
        if needle is None:  # pragma: no cover - the schema stopped declaring one
            pytest.skip("rule_sets has no inline FOREIGN KEY clause to duplicate")
        mutated = original.replace(needle, f"{needle}, {needle}", 1)

        mutate.execute("PRAGMA writable_schema=ON")
        mutate.execute("UPDATE sqlite_master SET sql=? WHERE type='table' AND name='rule_sets'", (mutated,))
        mutate.execute("PRAGMA writable_schema=OFF")
        mutate.commit()
    finally:
        mutate.close()

    reopened = sqlite3.connect(scratch_path)
    try:
        observed = referential_actions(reopened)
        if max(observed.values()) < 2:  # pragma: no cover - rewrite did not take
            pytest.skip("the stored-schema rewrite did not duplicate a constraint")
        assert "referential-action-added" in {v.kind for v in invariant(reopened)}
    finally:
        reopened.close()


def test_an_empty_string_column_name_is_still_mapped(scratch):
    """`column is not None`, not truthiness.

    SQLite permits a quoted empty-string column name and an ordinary index on
    it. `""` is falsy, so the index copy was dropped and the canonical count
    expected one physical copy where the permitted schema has two.
    """
    scratch.execute('CREATE TABLE empty_identifier ("" TEXT)')
    scratch.execute('CREATE INDEX empty_identifier_i ON empty_identifier("")')
    assert invariant(scratch) == [], "the invariant permits this table"

    locations = copy_map(scratch).locations(("empty_identifier", ""))
    assert "empty_identifier_i" in locations, dict(locations)
    assert sum(locations.values()) == 2


@pytest.mark.parametrize(
    "replacement",
    [
        None,
        "CREATE INDEX uq_collector_successful_ordinal ON collector_outcomes (device_id, ordinal) "
        "WHERE event_id IS NOT NULL",
        "CREATE UNIQUE INDEX uq_collector_successful_ordinal ON collector_outcomes (device_id, ordinal)",
        "CREATE UNIQUE INDEX uq_collector_successful_ordinal ON collector_outcomes (device_id, ordinal) "
        "WHERE event_id IS NULL",
        "CREATE UNIQUE INDEX uq_collector_successful_ordinal ON collector_outcomes (device_id, digest) "
        "WHERE event_id IS NOT NULL",
    ],
    ids=["missing", "nonunique", "unconditional", "inverted-predicate", "different-key"],
)
def test_receipt_index_drift_is_refused(scratch, replacement):
    scratch.execute("DROP INDEX uq_collector_successful_ordinal")
    if replacement:
        scratch.execute(replacement)
    assert any(v.detail == "uq_collector_successful_ordinal" for v in invariant(scratch))


def test_splitting_the_scoped_receipt_fk_is_refused(scratch):
    original = scratch.execute("SELECT sql FROM sqlite_schema WHERE name='collector_outcomes'").fetchone()[0]
    scope = "FOREIGN KEY(event_id, device_id) REFERENCES agent_observations (event_id, device_id) ON DELETE CASCADE"
    assert scope in original
    split = ", ".join(
        f"FOREIGN KEY({column}) REFERENCES agent_observations ({column}) ON DELETE CASCADE"
        for column in ("event_id", "device_id")
    )
    scratch.execute("DROP TABLE collector_outcomes")
    scratch.execute(original.replace(scope, split))
    violations = invariant(scratch)
    assert any(v.kind == "referential-action-removed" and "collector_outcomes" in v.detail for v in violations)


def test_receipt_copies_match_row_membership_and_vacuumed_bytes(scratch, scratch_path, tmp_path):
    from tests.release.attribution import Unattributed, attribute, expected_locations
    from tests.release.counts import canonical_live_image, check_capture_on
    from tests.release.store import Snapshot, delta

    before = Snapshot.take(scratch)
    path = ("collector_outcomes", "device_id")
    index = "uq_collector_successful_ordinal"
    rows = [
        ("accepted-receipt-canary", "accepted", None, "first-event", 4),
        ("duplicate-receipt-canary", "duplicate", None, "other-event", 4),
        ("rejected-receipt-canary", "rejected", "retired_ordinal", None, 3),
    ]
    # Isolate the receipt bytes from parent tables. This scratch database has
    # foreign_keys off; receipt CHECK constraints and every index remain live.
    with scratch:
        scratch.executemany(
            "INSERT INTO collector_outcomes (device_id, ordinal, digest, outcome, reason, event_id,"
            " received_at, expires_at)"
            " VALUES (?, 1, 'digest', ?, ?, ?, '2026-01-01', '2026-01-02')",
            [row[:4] for row in rows],
        )
    produced = attribute(scratch, delta(before, Snapshot.take(scratch)))
    image = canonical_live_image(scratch_path, tmp_path / "compact.db").read_bytes()
    for device_id, _, _, event_id, expected_count in rows:
        rowid = scratch.execute("SELECT rowid FROM collector_outcomes WHERE device_id=?", (device_id,)).fetchone()[0]
        indexed = event_id is not None
        for column in ("device_id", "ordinal"):
            assert (
                any(
                    a.path == ("collector_outcomes", column) and a.rowid == rowid and a.location == index
                    for a in produced
                )
                == indexed
            )
            assert (index in expected_locations(scratch, ("collector_outcomes", column), rowid=rowid)) == indexed
        actual_count = image.count(device_id.encode())
        assert actual_count == expected_count
        check_capture_on(scratch, path, actual_count, rowid=rowid)

    with pytest.raises(Unattributed, match="rowid"):
        expected_locations(scratch, path)
    with pytest.raises(Unattributed, match="rowid"):
        expected_locations(scratch, path, rowid=-1)


def test_a_receipt_becoming_indexed_attributes_even_unchanged_key_columns(scratch):
    from tests.release.attribution import attribute
    from tests.release.store import Snapshot, delta

    scratch.execute(
        "INSERT INTO collector_outcomes (device_id, ordinal, digest, outcome, reason, received_at, expires_at) "
        "VALUES ('device', 1, 'digest', 'rejected', 'retired_ordinal', '2026-01-01', '2026-01-02')"
    )
    before = Snapshot.take(scratch)
    scratch.execute("UPDATE collector_outcomes SET outcome='accepted', event_id='event', reason=NULL, ordinal=2")
    copies = attribute(scratch, delta(before, Snapshot.take(scratch)))
    assert sorted(a.path for a in copies if a.location == "uq_collector_successful_ordinal") == [
        ("collector_outcomes", "device_id"),
        ("collector_outcomes", "ordinal"),
    ]


@pytest.mark.parametrize("shadow", ["table", "index"])
def test_temp_names_do_not_hide_main_receipt_copies(scratch, shadow):
    from tests.release.attribution import Unattributed, expected_locations
    from tests.release.store import Snapshot

    scratch.execute(
        "INSERT INTO main.collector_outcomes (device_id, ordinal, digest, outcome, event_id, received_at, expires_at) "
        "VALUES ('main-device', 1, 'digest', 'accepted', 'event', '2026-01-01', '2026-01-02')"
    )
    if shadow == "table":
        scratch.execute("CREATE TEMP TABLE collector_outcomes (device_id TEXT, other TEXT)")
        scratch.execute("INSERT INTO temp.collector_outcomes VALUES ('temp-device', 'temp-only')")
    else:
        scratch.execute("CREATE TEMP TABLE unrelated (other TEXT)")
        scratch.execute("CREATE INDEX temp.uq_collector_successful_ordinal ON unrelated(other)")

    path = ("collector_outcomes", "device_id")
    assert invariant(scratch) == []
    assert Snapshot.take(scratch).cells[("collector_outcomes", 1, "device_id")] == "main-device"
    assert expected_locations(scratch, path, rowid=1)["uq_collector_successful_ordinal"] == 1
    with pytest.raises(Unattributed, match="rowid"):
        expected_locations(scratch, path)


def test_entering_a_receipt_index_accounts_for_its_implicit_rowid_slot():
    from tests.release.attribution import attribute
    from tests.release.store import Snapshot, delta

    with closing(sqlite3.connect(":memory:")) as db:
        db.execute(
            "CREATE TABLE collector_outcomes (id INTEGER PRIMARY KEY, device_id TEXT, ordinal INT, event_id TEXT)"
        )
        db.execute(
            "CREATE UNIQUE INDEX uq_collector_successful_ordinal ON collector_outcomes (device_id, ordinal) "
            "WHERE event_id IS NOT NULL"
        )
        db.execute("INSERT INTO collector_outcomes VALUES (1, 'device', 1, NULL)")
        before = Snapshot.take(db)
        db.execute("UPDATE collector_outcomes SET event_id='event'")
        copies = attribute(db, delta(before, Snapshot.take(db)))
        assert sorted(a.path[1] for a in copies if a.location == "uq_collector_successful_ordinal") == [
            "device_id",
            "id",
            "ordinal",
        ]


@pytest.mark.parametrize("change", ["COLLATE NOCASE", "DESC"])
def test_native_parent_index_collation_and_direction_are_pinned(scratch, change):
    scratch.execute("DROP INDEX uq_native_session_scope")
    scratch.execute(
        "CREATE UNIQUE INDEX uq_native_session_scope ON agent_sessions "
        f"(session_id,device_id,policy_id,agent,native_session_token {change})"
    )
    assert any(v.kind == "native-index-slots" and v.detail == "agent_sessions" for v in invariant(scratch))
