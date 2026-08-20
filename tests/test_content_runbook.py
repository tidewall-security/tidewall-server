"""The operator runbook, executed rather than read.

Every test here runs text extracted from `docs/operations/content-runbook.md`
or the script it publishes. A test that reimplemented either would prove only
that the reimplementation works, and the runbook could drift away from it
silently -- which is the failure this whole step exists to prevent.

One deliberate gap, stated rather than implied: `scan-artifacts.sh` ends with a
`scanned=0` backstop that no test here kills. On a stable filesystem the
database-existence check always fires first, so the backstop is reachable only
if an artifact disappears between that check and the loop. It stays for that
race. Do not add a test that appears to cover it.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
RUNBOOK = REPO / "docs" / "operations" / "content-runbook.md"
SCAN = REPO / "scripts" / "scan-artifacts.sh"

CANARY = "CANARY-SWORDFISH-42"


def _run_scan(db, *canaries):
    return subprocess.run([str(SCAN), str(db), *canaries], capture_output=True, text=True, cwd=REPO)


def _sqlite_file(path, contents=None):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t(x)")
    if contents is not None:
        conn.execute("INSERT INTO t VALUES(?)", (contents,))
    conn.commit()
    conn.close()


def _scan_case(tmp_path, case):
    """Return (db_path, canaries) for one case.

    `absent_database_with_sidecar` and `no_artifact_at_all` are separate
    fixtures on purpose: an all-absent state exits at the database check
    whether or not that check exists, so only a sidecar-only state binds it.
    """
    db = tmp_path / "t.db"
    if case == "clean":
        _sqlite_file(db, "nothing interesting")
    elif case == "clean_with_persistent_shm":
        _sqlite_file(db, "nothing interesting")
        (tmp_path / "t.db-shm").write_bytes(b"\x00" * 32)
    elif case == "regex_metacharacter_absent":
        _sqlite_file(db, "nothing interesting")
        return db, (".*",)
    elif case == "found":
        _sqlite_file(db, "nothing interesting")
        (tmp_path / "t.db-shm").write_text(CANARY)
    elif case == "no_canary":
        _sqlite_file(db, "nothing interesting")
        return db, ()
    elif case == "empty_canary":
        _sqlite_file(db, "nothing interesting")
        return db, ("",)
    elif case == "one_empty_among_several":
        _sqlite_file(db, "nothing interesting")
        return db, (CANARY, "", "other")
    elif case == "absent_database_with_sidecar":
        (tmp_path / "t.db-wal").write_bytes(b"\x00" * 32)
    elif case == "no_artifact_at_all":
        pass
    else:  # pragma: no cover - a typo in the parametrisation
        raise AssertionError(case)
    return db, (CANARY,)


@pytest.mark.parametrize(
    "case,expected",
    [
        ("clean", 0),
        ("clean_with_persistent_shm", 0),
        ("regex_metacharacter_absent", 0),
        ("found", 1),
        ("no_canary", 2),
        ("empty_canary", 2),
        ("one_empty_among_several", 2),
        ("absent_database_with_sidecar", 2),
        ("no_artifact_at_all", 2),
    ],
)
def test_the_scan_reports_three_distinct_outcomes(tmp_path, case, expected):
    """0 scanned-and-clean, 1 found, 2 could-not-scan.

    The third status is the point. An earlier version of this script folded
    "could not scan" into "nothing found": with a clean persistent -shm the
    final grep returned 1 and became the exit status, and with the database
    absent every loop iteration was skipped and it reported clean.
    """
    db, canaries = _scan_case(tmp_path, case)
    assert _run_scan(db, *canaries).returncode == expected


@pytest.mark.parametrize("break_it", ["directory", "unreadable"])
def test_a_scan_that_could_not_read_an_artifact_is_not_a_clean_result(tmp_path, break_it):
    """The third status exists for exactly this.

    A sidecar that cannot be read leaves the question unanswered. Folding
    grep's error status into "nothing found" would report a database as clean
    on the strength of a scan that never happened.
    """
    db = tmp_path / "t.db"
    _sqlite_file(db, "nothing interesting")
    shm = tmp_path / "t.db-shm"
    if break_it == "directory":
        shm.mkdir()
    else:
        shm.write_text("x")
        shm.chmod(0)
        if _run_scan(db, CANARY).returncode == 0:  # pragma: no cover
            pytest.skip("running as a user for whom mode 0 is readable")

    result = _run_scan(db, CANARY)
    assert result.returncode == 2, result.stdout
    assert "scan FAILED" in result.stdout


def test_a_canary_is_matched_literally_not_as_a_pattern(tmp_path):
    """`.*` is a string an operator might plausibly be searching for, and it
    must not match everything. Without grep -F it reported a find for a canary
    that was absent."""
    db = tmp_path / "t.db"
    _sqlite_file(db, "nothing interesting")
    assert _run_scan(db, ".*").returncode == 0
    (tmp_path / "t.db-shm").write_text("literally .* here")
    assert _run_scan(db, ".*").returncode == 1


# --------------------------------------------------------------------------
# Task 3: the published session block is the whole program
# --------------------------------------------------------------------------


def _extract(marker: str) -> str:
    """The one fenced block under `marker`. Fails unless there is exactly one."""
    blocks = re.findall(rf"<!-- {re.escape(marker)} -->\s*```bash\n(.*?)```", RUNBOOK.read_text(), re.S)
    assert len(blocks) == 1, f"expected exactly one {marker} block, found {len(blocks)}"
    return blocks[0]


def _sql_statements(block: str) -> list[str]:
    """The SQL and dot-commands inside the block's heredoc, in order.

    Three details, each of which a naive implementation gets wrong:

    * take only the heredoc body -- between the line opening it and the line
      that is exactly ``SQL`` -- or the shell prologue and epilogue come too;
    * drop full-line ``--`` comments, and only those. A general comment
      stripper rewrites SQL it has no business touching;
    * take each line beginning ``.`` as its own entry BEFORE splitting the rest
      on ``;``, or ``.bail on`` is joined to the statement after it.
    """
    lines = block.splitlines()
    start = next(i for i, line in enumerate(lines) if "<<SQL" in line)
    end = next(i for i, line in enumerate(lines) if i > start and line.strip() == "SQL")
    body = [line for line in lines[start + 1 : end] if not line.strip().startswith("--")]

    statements: list[str] = []
    buffer: list[str] = []
    for line in body:
        if line.startswith("."):
            assert not buffer, f"a dot-command interrupted a statement: {line!r}"
            statements.append(line.strip())
            continue
        buffer.append(line)
        if line.rstrip().endswith(";"):
            # Stripped: a blank line before a statement is not part of it, and
            # leaving it attached made `.index("PRAGMA wal_checkpoint...")`
            # find the SECOND checkpoint rather than the first.
            statements.append("\n".join(buffer).strip())
            buffer = []
    assert not [line for line in buffer if line.strip()], f"unterminated statement: {buffer!r}"
    return statements


def _norm(text: str) -> str:
    return " ".join(text.split())


#: Every statement the session block may contain, in order. Compared exactly
#: after whitespace normalisation -- not by prefix. `startswith` accepts
#: `INSERT INTO _assert SELECT 'integrity ok', 1;`, which keeps the label and
#: deletes the predicate, and accepts `VACUUM INTO 'elsewhere.db'`.
_PERMITTED = [
    ".bail on",
    "CREATE TEMP TABLE _assert(what TEXT, ok INT NOT NULL CHECK(ok=1));",
    "INSERT INTO _assert SELECT 'journal mode is wal', journal_mode='wal' FROM pragma_journal_mode;",
    "INSERT INTO _assert SELECT 'exactly one expected revision', "
    "(SELECT count(*) FROM alembic_version WHERE version_num='$REV')=1 "
    "AND (SELECT count(*) FROM alembic_version)=1;",
    "INSERT INTO _assert SELECT 'both are tables, not views', "
    "(SELECT count(*) FROM sqlite_schema WHERE type='table' "
    "AND name IN ('interactions','interaction_contents'))=2;",
    "INSERT INTO _assert SELECT 'interactions is the head shape', "
    "(SELECT count(*) FROM pragma_table_xinfo('interactions'))=20 "
    "AND (SELECT count(*) FROM pragma_table_xinfo('interactions') "
    "WHERE name IN ('id','request_id','timestamp','event_type','policy_id', "
    "'policy_name','api_key_id','blocked','transformed', "
    "'latency_ms','app_id','user_id','llm_provider','model', "
    "'source_ip','status','device_id','evidence_json', "
    "'evidence_schema_version','content_available'))=20;",
    "INSERT INTO _assert SELECT 'interaction_contents is the head shape', "
    "(SELECT count(*) FROM pragma_table_xinfo('interaction_contents'))=9 "
    "AND (SELECT count(*) FROM pragma_table_xinfo('interaction_contents') "
    "WHERE name IN ('id','interaction_id','input_json','output_json','matches_json', "
    "'byte_size','captured_at','expires_at','policy_id'))=9;",
    "INSERT INTO _assert SELECT 'legacy content columns are gone', "
    "NOT EXISTS(SELECT 1 FROM pragma_table_info('interactions') "
    "WHERE name IN ('input_messages','output_messages', "
    "'detectors_json','summary'));",
    "INSERT INTO _assert SELECT 'no content rows remain', " "(SELECT count(*) FROM interaction_contents)=0;",
    "PRAGMA wal_checkpoint(TRUNCATE);",
    "VACUUM;",
    "PRAGMA wal_checkpoint(TRUNCATE);",
    "INSERT INTO _assert SELECT 'integrity ok', integrity_check='ok' FROM pragma_integrity_check;",
    "SELECT 'SEQUENCE-COMPLETE';",
]


def test_the_session_block_is_exactly_the_permitted_program():
    """Not "the expected statements appear in order" -- that nothing else
    appears at all, and that each one is what it claims to be."""
    got = [_norm(s) for s in _sql_statements(_extract("runbook:session"))]
    assert got == [_norm(s) for s in _PERMITTED]


# --------------------------------------------------------------------------
# Task 4: the preconditions refuse, and refuse before writing anything
# --------------------------------------------------------------------------

HEAD_REVISION = "1b42ababed28"
#: The columns head actually has, read from a migrated database by
#: `_assert_fixture_shape` rather than trusted from here.
HEAD_INTERACTIONS_COLUMNS = 20
HEAD_CONTENTS_COLUMNS = 9


def _alembic(db, *args):
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO,
        env={**os.environ, "DB_URL": f"sqlite:///{db}"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr[-2000:]


def _assert_fixture_shape(db):
    """If the schema moves, fail here and say so.

    Otherwise the runbook would go on guarding a shape the database no longer
    has, and every rejection test would keep passing for the wrong reason.
    """
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone()[0] == HEAD_REVISION
        for table, expected in (
            ("interactions", HEAD_INTERACTIONS_COLUMNS),
            ("interaction_contents", HEAD_CONTENTS_COLUMNS),
        ):
            got = conn.execute(f"SELECT count(*) FROM pragma_table_xinfo('{table}')").fetchone()[0]
            assert got == expected, (
                f"{table} now has {got} columns, not {expected}. The runbook's guard "
                "needs updating before this suite means anything."
            )
    finally:
        conn.close()


def _head_db(tmp_path):
    """A WAL database at head, in two explicit stages.

    `alembic upgrade head` leaves the database in `delete` mode -- verified --
    and `get_engine` sets WAL from a *connect* listener, so constructing the
    engine is not enough. These are two operations and the fixture does both.
    """
    from app.db.engine import get_engine

    db = tmp_path / "head.db"
    _alembic(db, "upgrade", "head")
    engine = get_engine(f"sqlite:///{db}")
    with engine.connect():
        pass
    engine.dispose()
    _assert_fixture_shape(db)
    return db


def _run_session(db, revision=HEAD_REVISION):
    """Run the published session block against `db`.

    Only the two assignment templates are replaced, and both must be found:
    the published `REV=<the alembic revision this deployment expects>` is not
    even valid shell, so a syntax or lint check over the raw block fails on the
    template rather than on the program.
    """
    block = _substituted_session(db, revision)
    return subprocess.run(["bash", "-c", block], capture_output=True, text=True, cwd=REPO)


def _substituted_session(db, revision=HEAD_REVISION) -> str:
    """The published block with its two assignment templates filled in."""
    block = _extract("runbook:session")
    block, db_subs = re.subn(r"(?m)^DB=.*$", f"DB={shlex.quote(str(db))}", block, count=1)
    block, rev_subs = re.subn(r"(?m)^REV=.*$", f"REV={shlex.quote(revision)}", block, count=1)
    assert db_subs == 1 and rev_subs == 1, "the block's assignment templates moved"
    return block


def _sql(db, *statements):
    conn = sqlite3.connect(db)
    try:
        for statement in statements:
            conn.execute(statement)
        conn.commit()
    finally:
        conn.close()


_HEAD_INTERACTIONS = (
    "id INTEGER PRIMARY KEY, request_id TEXT, timestamp TEXT, event_type TEXT, "
    "policy_id TEXT, policy_name TEXT, api_key_id TEXT, blocked INT, transformed INT, "
    "latency_ms REAL, app_id TEXT, user_id TEXT, llm_provider TEXT, model TEXT, "
    "source_ip TEXT, status TEXT, device_id TEXT, evidence_json TEXT, "
    "evidence_schema_version INT, content_available INT"
)
_HEAD_CONTENTS = (
    "id INTEGER PRIMARY KEY, interaction_id INT, input_json TEXT, output_json TEXT, "
    "matches_json TEXT, byte_size INT, captured_at TEXT, expires_at TEXT, policy_id TEXT"
)
_VIEW_INTERACTIONS = ", ".join(
    f"1 AS {name}"
    for name in _HEAD_INTERACTIONS.replace(" INTEGER PRIMARY KEY", "").split(", ")
    for name in [name.split()[0]]
)
_VIEW_CONTENTS = ", ".join(f"1 AS {name.split()[0]}" for name in _HEAD_CONTENTS.split(", "))


def _live_content_row(db):
    """A parent interaction and one content row, so that `no content rows
    remain` is the ONLY failing precondition. Without a valid parent the
    fixture could fail for a reason that has nothing to do with the guard."""
    _sql(
        db,
        "INSERT INTO interactions (id, request_id, timestamp, event_type, policy_id, "
        "policy_name, blocked, transformed, latency_ms, evidence_schema_version, "
        "content_available) VALUES (1, 'tw_00000000000000aa', '2026-08-20T00:00:00Z', "
        "'input', 'policy-a', 'policy-a', 0, 0, 1.0, 1, 1)",
        "INSERT INTO interaction_contents (interaction_id, policy_id, byte_size, captured_at) "
        "VALUES (1, 'policy-a', 10, '2026-08-20 00:00:00.000000')",
    )


#: One fixture per row. The count is what the table has, not a headline over it.
_DAMAGE = {
    "1_journal_mode_delete": lambda db: _sql(db, "PRAGMA journal_mode=DELETE"),
    "2_wrong_revision": lambda db: _sql(db, "UPDATE alembic_version SET version_num='deadbeef'"),
    "3_empty_alembic_version": lambda db: _sql(db, "DELETE FROM alembic_version"),
    # alembic_version is NOT NULL with a primary key, so these two states are
    # reached by rebuilding the table without those constraints. What matters
    # is the state the runbook meets, not how the fixture arrived at it.
    "4_null_version_num": lambda db: _sql(
        db,
        "DROP TABLE alembic_version",
        "CREATE TABLE alembic_version (version_num VARCHAR(32))",
        "INSERT INTO alembic_version VALUES(NULL)",
    ),
    # The expected revision AND a stray one. Two identical rows would be
    # rejected by the first conjunct (its matching count becomes 2), so that
    # shape leaves `(SELECT count(*) FROM alembic_version)=1` unbound -- the
    # mutation survived until this fixture was changed. This is the state that
    # conjunct exists for.
    "5_more_than_one_revision_row": lambda db: _sql(
        db,
        "DROP TABLE alembic_version",
        "CREATE TABLE alembic_version (version_num VARCHAR(32))",
        f"INSERT INTO alembic_version VALUES('{HEAD_REVISION}')",
        "INSERT INTO alembic_version VALUES('a-stray-revision')",
    ),
    "6_no_alembic_version_table": lambda db: _sql(db, "DROP TABLE alembic_version"),
    "7_legacy_input_messages": lambda db: _sql(db, "ALTER TABLE interactions ADD COLUMN input_messages TEXT"),
    "8_legacy_output_messages": lambda db: _sql(db, "ALTER TABLE interactions ADD COLUMN output_messages TEXT"),
    "9_legacy_detectors_json": lambda db: _sql(db, "ALTER TABLE interactions ADD COLUMN detectors_json TEXT"),
    "10_legacy_summary": lambda db: _sql(db, "ALTER TABLE interactions ADD COLUMN summary TEXT"),
    "11_interactions_dropped": lambda db: _sql(db, "DROP TABLE interactions"),
    "12_interactions_one_column": lambda db: _sql(db, "DROP TABLE interactions", "CREATE TABLE interactions(id INT)"),
    "13_evidence_json_dropped": lambda db: _sql(db, "ALTER TABLE interactions DROP COLUMN evidence_json"),
    "14_interactions_counted_names_only": lambda db: _sql(
        db,
        "DROP TABLE interactions",
        "CREATE TABLE interactions(evidence_json TEXT, evidence_schema_version INT, " "content_available INT)",
    ),
    "15_contents_one_column": lambda db: _sql(
        db, "DROP TABLE interaction_contents", "CREATE TABLE interaction_contents(id INT)"
    ),
    "16_contents_counted_names_only": lambda db: _sql(
        db,
        "DROP TABLE interaction_contents",
        "CREATE TABLE interaction_contents(interaction_id INT, input_json TEXT, "
        "output_json TEXT, matches_json TEXT, byte_size INT, captured_at TEXT, expires_at TEXT)",
    ),
    "17_interactions_is_a_view": lambda db: _sql(
        db, "DROP TABLE interactions", f"CREATE VIEW interactions AS SELECT {_VIEW_INTERACTIONS} WHERE 0"
    ),
    "18_contents_is_a_view": lambda db: _sql(
        db,
        "DROP TABLE interaction_contents",
        f"CREATE VIEW interaction_contents AS SELECT {_VIEW_CONTENTS} WHERE 0",
    ),
    # `id` is a primary key and `policy_id` is indexed, so SQLite refuses to
    # drop either in place; the table is rebuilt without them.
    "19_contents_missing_id": lambda db: _sql(
        db,
        "DROP TABLE interaction_contents",
        "CREATE TABLE interaction_contents(interaction_id INT, input_json TEXT, "
        "output_json TEXT, matches_json TEXT, byte_size INT, captured_at TEXT, "
        "expires_at TEXT, policy_id TEXT)",
    ),
    "20_contents_missing_policy_id": lambda db: _sql(
        db,
        "DROP TABLE interaction_contents",
        "CREATE TABLE interaction_contents(id INTEGER PRIMARY KEY, interaction_id INT, "
        "input_json TEXT, output_json TEXT, matches_json TEXT, byte_size INT, "
        "captured_at TEXT, expires_at TEXT)",
    ),
    "21_ordinary_column_renamed": lambda db: _sql(
        db, "ALTER TABLE interactions RENAME COLUMN source_ip TO source_ip_typo"
    ),
    "22_twenty_first_column": lambda db: _sql(db, "ALTER TABLE interactions ADD COLUMN extra TEXT"),
    "23_virtual_generated_column": lambda db: _sql(
        db,
        "ALTER TABLE interactions ADD COLUMN gen TEXT GENERATED ALWAYS AS (source_ip) VIRTUAL",
    ),
    "24_stored_generated_column": lambda db: _sql(
        db,
        "ALTER TABLE interaction_contents ADD COLUMN gen TEXT " "GENERATED ALWAYS AS (policy_id) STORED",
    ),
    "25_drop_plus_add_same_total": lambda db: _sql(
        db,
        "ALTER TABLE interactions DROP COLUMN source_ip",
        "ALTER TABLE interactions ADD COLUMN something_else TEXT",
    ),
    "26_live_content_row": _live_content_row,
}


def test_the_matrix_has_one_fixture_per_named_state():
    """Derived from the table, not asserted over it. An earlier plan claimed
    twenty-four while enumerating a phrase list that resolved to thirteen,
    fourteen or fifteen depending on how two entries were read."""
    assert len(_DAMAGE) == 26


def test_a_correct_database_is_reclaimed(tmp_path):
    db = _head_db(tmp_path)
    result = _run_session(db)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count("0|0|0") == 2, result.stdout
    assert "SEQUENCE-COMPLETE" in result.stdout


@pytest.mark.parametrize("damage", sorted(_DAMAGE, key=lambda k: int(k.split("_")[0])))
def test_a_wrong_database_is_refused_before_anything_is_written(tmp_path, damage):
    db = _head_db(tmp_path)
    _DAMAGE[damage](db)
    before = hashlib.sha256(db.read_bytes()).hexdigest()

    result = _run_session(db)

    assert result.returncode != 0, f"the sequence ran: {result.stdout}"
    assert (
        hashlib.sha256(db.read_bytes()).hexdigest() == before
    ), "the database was mutated before the refusal; a guard that fails late is not a guard"


# --------------------------------------------------------------------------
# Task 5: the post-close block, and the two checkpoints
# --------------------------------------------------------------------------

#: Four values that cannot match each other. Real representations of one
#: string can overlap -- the plain form is a substring of most escapings -- so
#: "only this one is present" would not prove that a dropped argument was
#: missed by the others.
_SENTINELS = {
    "CANARY_PLAIN": "SENTINEL-ALPHA-11111",
    "CANARY_JSON": "SENTINEL-BRAVO-22222",
    "CANARY_UNICODE": "SENTINEL-CHARLIE-33333",
    "CANARY_RAW": "SENTINEL-DELTA-44444",
}


def _run_postclose(db, **overrides):
    """Run the published post-close block.

    No substitution at all: the block reads `${VAR:?}`, so the values arrive
    through the environment and the published text runs unmodified.
    """
    env = {**os.environ, "DB": str(db), **_SENTINELS, **overrides}
    return subprocess.run(
        ["bash", "-c", _extract("runbook:postclose")],
        capture_output=True,
        text=True,
        cwd=REPO,
        env=env,
    )


def _clean_reclaimed_db(tmp_path):
    db = _head_db(tmp_path)
    assert _run_session(db).returncode == 0
    return db


def test_the_post_close_block_passes_after_a_clean_session(tmp_path):
    result = _run_postclose(_clean_reclaimed_db(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_post_close_block_refuses_a_wal_that_was_not_truncated(tmp_path):
    db = _clean_reclaimed_db(tmp_path)
    pathlib.Path(f"{db}-wal").write_bytes(b"\x00" * 64)
    result = _run_postclose(db)
    assert result.returncode == 1
    assert "WAL not truncated" in result.stdout


def test_the_post_close_block_refuses_a_rollback_journal(tmp_path):
    db = _clean_reclaimed_db(tmp_path)
    pathlib.Path(f"{db}-journal").write_bytes(b"")
    result = _run_postclose(db)
    assert result.returncode == 1
    assert "rollback journal" in result.stdout


@pytest.mark.parametrize("variable", sorted(_SENTINELS))
def test_the_post_close_block_passes_every_representation_to_the_scan(tmp_path, variable):
    """One case per argument, each with only that sentinel present.

    A single mixed case would pass even if the published command silently
    dropped `$CANARY_UNICODE` or `$CANARY_RAW`, because another argument would
    still find something. Binding the wiring needs one case per argument.
    """
    db = _clean_reclaimed_db(tmp_path)
    pathlib.Path(f"{db}-shm").write_text(_SENTINELS[variable])
    result = _run_postclose(db)
    assert result.returncode == 1, f"{variable} was not passed to the scan: {result.stdout}"
    assert "FOUND" in result.stdout


@pytest.mark.parametrize("variable", sorted(_SENTINELS) + ["DB"])
def test_the_post_close_block_refuses_to_run_without_its_inputs(tmp_path, variable):
    """`${VAR:?}` rejects unset and empty. A block that ran with an empty
    canary would hand the scan an argument it must refuse anyway, but the
    refusal belongs at the top where the operator sees it."""
    db = _clean_reclaimed_db(tmp_path)
    result = _run_postclose(db, **{variable: ""})
    assert result.returncode != 0


def test_the_second_checkpoint_is_what_truncates_the_wal(tmp_path):
    """Held open by an observer, so the CLI's exit is not a last close.

    Without the observer, SQLite's own last-connection handling checkpoints and
    deletes the WAL, and this assertion passes whether or not the second
    checkpoint is there at all. That is how an earlier version of this test
    passed against a build with the checkpoint removed.

    The observer protocol matters too: attached, its statement fully consumed
    and finalised, holding no transaction. One that pins a read snapshot makes
    the checkpoints return busy, and the test then fails for its own fixture
    rather than for the mutation -- which is why the row assertion comes first.
    """
    db = _head_db(tmp_path)
    observer = sqlite3.connect(db)
    observer.execute("PRAGMA journal_mode").fetchall()
    try:
        result = _run_session(db)
        assert result.returncode == 0, result.stdout + result.stderr
        assert (
            result.stdout.count("0|0|0") == 2
        ), f"a checkpoint reported busy -- the observer is pinning frames: {result.stdout}"
        wal = pathlib.Path(f"{db}-wal")
        assert not wal.exists() or wal.stat().st_size == 0, f"the WAL was not truncated: {wal.stat().st_size} bytes"
    finally:
        observer.close()


def _feed(process, statements, sentinel):
    """Feed statements to a live sqlite3 session, framed so the read ends.

    Without the sentinel a read for an expected row blocks when that row is not
    produced -- which is exactly the state a removed checkpoint creates.
    """
    for statement in statements:
        process.stdin.write(statement + "\n")
    process.stdin.write(f"SELECT '{sentinel}';\n")
    process.stdin.flush()
    rows = []
    while True:
        line = process.stdout.readline()
        if not line:
            raise AssertionError(f"the session ended before {sentinel}: {rows}")
        line = line.strip()
        if line == sentinel:
            return rows
        if line:
            rows.append(line)


def test_the_first_checkpoint_reports_its_own_result(tmp_path):
    """The one place the block is not run as a single published unit.

    `out=$(...)` captures everything until the CLI exits, so no caller can read
    the first checkpoint's row mid-session. The SQL still comes from the
    runbook via `_sql_statements`; only the framing is the test's.
    """
    db = _head_db(tmp_path)
    statements = _sql_statements(_extract("runbook:session"))
    first = statements.index("PRAGMA wal_checkpoint(TRUNCATE);")

    # Pin an old snapshot, then commit frames beyond it.
    reader = sqlite3.connect(db)
    reader.execute("BEGIN")
    reader.execute("SELECT count(*) FROM interactions").fetchall()
    writer = sqlite3.connect(db)
    writer.execute("CREATE TABLE probe(x)")
    writer.commit()

    process = subprocess.Popen(
        ["sqlite3", str(db)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    try:
        phase_one = _feed(process, statements[first : first + 1], "PHASE-1-END")
        assert len(phase_one) == 1, f"expected exactly the first checkpoint's row: {phase_one}"
        assert phase_one[0].startswith(
            "1|"
        ), f"the first checkpoint did not report busy against a pinned reader: {phase_one[0]}"

        reader.close()

        phase_two = _feed(process, statements[first + 1 : first + 3], "PHASE-2-END")
        assert phase_two == ["0|0|0"], f"the second checkpoint did not complete once the reader was gone: {phase_two}"
    finally:
        process.stdin.close()
        process.wait(timeout=30)
        writer.close()


# --------------------------------------------------------------------------
# Task 6: the canary transition, and the documentation gates
# --------------------------------------------------------------------------


def _plant_canary(db, representations, page_size):
    """Leave every representation as deleted residue in BOTH the main file and
    the WAL, with `interaction_contents` empty again afterwards.

    Three details, each of which makes the fixture wrong if omitted:

    * `secure_delete=OFF` explicitly. With it ON or FAST the delete scrubs the
      WAL page image and every representation lands only in the main file --
      and the two SQLite builds in this checkout disagree on the default (0 for
      the Python module, 2 for /usr/bin/sqlite3).
    * a checkpoint after the insert. Holding a connection preserves a sidecar;
      it does not move inserted pages into the main file, so without this the
      canary is in the WAL and nowhere else.
    * `page_size` before the schema exists, or it is ignored.
    """
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA secure_delete=OFF")
    assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 0
    conn.execute(f"PRAGMA page_size={page_size}")
    conn.execute("PRAGMA journal_mode=WAL")
    # One content row per interaction: interaction_contents.interaction_id is
    # unique, so four representations need four parents.
    for index, text in enumerate(representations, start=1):
        conn.execute(
            "INSERT INTO interactions (id, request_id, timestamp, event_type, policy_id, "
            "policy_name, blocked, transformed, latency_ms, evidence_schema_version, "
            "content_available) VALUES (?, ?, '2026-08-20T00:00:00Z', 'input', 'policy-a', "
            "'policy-a', 0, 0, 1.0, 1, 1)",
            (index, f"tw_{index:016x}"),
        )
        conn.execute(
            "INSERT INTO interaction_contents (interaction_id, policy_id, input_json, "
            "byte_size, captured_at) VALUES (?, 'policy-a', ?, 10, '2026-08-20 00:00:00.000000')",
            (index, text),
        )
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # into the main file
    conn.execute("DELETE FROM interaction_contents")
    conn.execute("DELETE FROM interactions")
    conn.commit()  # residue: main-file free pages AND WAL frames
    return conn  # held open, so the copy carries a live WAL


def _copy_database(db, destination):
    destination.mkdir(parents=True, exist_ok=True)
    copied = destination / db.name
    for suffix in ("", "-wal", "-shm"):
        source = pathlib.Path(f"{db}{suffix}")
        if source.exists():
            shutil.copy2(source, pathlib.Path(f"{copied}{suffix}"))
    return copied


@pytest.mark.parametrize("page_size", [512, 4096, 65536])
def test_the_procedure_removes_every_representation_from_both_artifacts(tmp_path, page_size):
    """The whole point, end to end.

    The four representations are planted as residue in the main file and the
    WAL, asserted present in the COPY -- not in the original, which proves only
    that the source was dirty at the end -- and then the published session and
    the published scan script are run against that copy.
    """
    representations = [
        "canary-plain-éé",
        json.dumps("canary-plain-éé"),
        "canary-\\u0070lain-escaped",
        "canary-raw-\x01\x02bytes",
    ]

    db = _head_db(tmp_path)
    holder = _plant_canary(db, representations, page_size)
    try:
        copy = _copy_database(db, tmp_path / "copy")
        main_bytes = copy.read_bytes()
        wal = pathlib.Path(f"{copy}-wal")
        assert wal.exists(), "the copy carries no WAL, so it cannot show WAL cleanup"
        wal_bytes = wal.read_bytes()
        for text in representations:
            encoded = text.encode()
            assert encoded in main_bytes, f"{text!r} is not in the copied main file"
            assert encoded in wal_bytes, f"{text!r} is not in the copied WAL"
    finally:
        holder.close()

    assert _run_session(copy).returncode == 0
    assert _run_scan(copy, *representations).returncode == 0


def test_the_runbook_publishes_exactly_one_of_each_block():
    _extract("runbook:session")
    _extract("runbook:postclose")


def test_the_changelog_points_at_the_runbook():
    changelog = (REPO / "CHANGELOG.md").read_text()
    assert "docs/operations/content-runbook.md" in changelog
    assert "destructive" in changelog.lower()


def test_every_relative_link_in_the_runbook_resolves():
    text = RUNBOOK.read_text()
    for target in re.findall(r"\]\((?!https?:)([^)#]+)", text):
        assert (RUNBOOK.parent / target).resolve().exists(), target


def test_the_published_shell_passes_shellcheck():
    """Over the SUBSTITUTED session block, not the raw one.

    The published `REV=<the alembic revision this deployment expects>` is not
    valid shell -- a check over the raw text fails on the template rather than
    on the program, which would be a gate that reports on the wrong thing.
    """
    for name, script in (
        ("scan-artifacts.sh", SCAN.read_text()),
        ("session", _substituted_session("/tmp/example.db", HEAD_REVISION)),
        ("postclose", _extract("runbook:postclose")),
    ):
        result = subprocess.run(
            ["uv", "run", "shellcheck", "--shell=bash", "-"],
            input=script,
            capture_output=True,
            text=True,
            cwd=REPO,
        )
        assert result.returncode == 0, f"{name}:\n{result.stdout}"


# --------------------------------------------------------------------------
# Task 7: the rehearsal record (the release gate)
# --------------------------------------------------------------------------

REHEARSAL = REPO / "docs" / "operations" / "rehearsals" / "2026-08-20-migration-rehearsal.md"


def test_the_rehearsal_record_is_complete():
    """The release gate. It fails while any field is outstanding.

    Three of the four are produced by the rehearsal itself and are populated.
    `Owner` names the person accountable for the backup taken before a real
    upgrade; a test run cannot produce it, and inventing it would make the
    acceptance record a fiction. So this test fails until an operator supplies
    it -- which is what a release-blocking input means.
    """
    assert REHEARSAL.exists(), REHEARSAL

    rows = dict(re.findall(r"^\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|$", REHEARSAL.read_text(), re.M))
    outstanding = []
    for field in ("Backup identifiers", "Owner", "Retention or deletion disposition", "Date"):
        value = rows.get(field, "")
        if not value or "OUTSTANDING" in value:
            outstanding.append(field)

    assert not outstanding, (
        f"the rehearsal record is incomplete: {outstanding}. "
        "This is the release gate, not a formatting check -- see the record's "
        "'Outstanding' section for what is missing and why it cannot be invented."
    )
