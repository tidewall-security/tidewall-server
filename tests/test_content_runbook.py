"""The operator runbook, executed rather than read.

Every test that RUNS a procedure runs text extracted from
`docs/operations/content-runbook.md` or the script it publishes. A test that
reimplemented either would prove only that the reimplementation works, and the
runbook could drift away from it silently.

Not every test executes something: the whitelists compare extracted text
against an expected program, and the link, lint, fixture-shape and rehearsal
tests inspect artifacts rather than running them. The universal claim would be
false, and this file is about not making those.

What pinning cannot do, stated because it is the boundary of this whole
approach: every pin here was generated FROM the artifact it guards. Change the
artifact, regenerate the pin, and the suite goes green -- that is not a hole to
be closed, it is what a pin is. What it buys is that the change becomes
impossible to make *silently*: it turns a one-line edit in a Markdown file into
a two-file diff with an expected-value change in a test, which is exactly the
shape a reviewer notices. The gate is the diff; these tests make sure there is
one.

Where the block gates stop: they cover BLOCK-level code -- fenced blocks,
indented blocks, raw HTML. They do not cover inline code spans, and cannot: the
runbook is full of them, because that is how prose names a command or a
variable. An inline span is not how this runbook gives an instruction to run
something -- every procedure here is a fenced block -- but a reviewer of a
change to this document still has to read its prose. That is a boundary, stated,
not a gap being ignored.

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
import unicodedata

import pytest

#: How the session block opens its heredoc. Quoted, so the shell performs no
#: expansion inside it -- see the runbook's "Why the heredoc is quoted".
_HEREDOC_OPEN = "<<'SQL'"

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


@pytest.mark.parametrize("artifact", ["", "-wal", "-shm"])
def test_the_scan_searches_every_artifact_it_names(tmp_path, artifact):
    """One positive case per artifact.

    With the canary only ever planted in the -shm, the loop could drop the WAL
    entirely -- or skip the main database while still counting it as scanned --
    and every other test stayed green. "Nothing was found" only means something
    if each named artifact was actually searched.
    """
    db = tmp_path / "t.db"
    _sqlite_file(db, CANARY if not artifact else "nothing interesting")
    target = pathlib.Path(f"{db}{artifact}")
    if artifact:
        target.write_text(CANARY)

    result = _run_scan(db, CANARY)
    assert result.returncode == 1, f"{target.name} was not searched: {result.stdout}"
    assert target.name in result.stdout


@pytest.mark.parametrize("canary", ["-n", "-e", "--", "-v"])
def test_a_canary_that_looks_like_an_option_is_still_a_canary(tmp_path, canary):
    """`grep -e` and `--` are load-bearing, not stylistic.

    Without `-e`, a canary of `-n` is consumed as an option: the script reports
    clean for a database that contains it. The existing `.*` case binds `-F`
    and nothing else.
    """
    db = tmp_path / "t.db"
    _sqlite_file(db, f"prefix {canary} suffix")
    assert _run_scan(db, canary).returncode == 1, f"a canary of {canary!r} was not searched for"

    clean = tmp_path / "clean.db"
    _sqlite_file(clean, "nothing interesting")
    assert _run_scan(clean, canary).returncode == 0


def test_a_database_path_that_looks_like_an_option_is_still_a_path(tmp_path):
    """`--` protects the operand, which `-e` does not.

    Only reachable through a relative path beginning with a dash, which is
    unlikely but costs one token to defend. Without `--`, grep reads the
    filename as options.
    """
    db = tmp_path / "-dashed.db"
    _sqlite_file(db, CANARY)
    result = subprocess.run([str(SCAN), "-dashed.db", CANARY], capture_output=True, text=True, cwd=tmp_path)
    assert result.returncode == 1, f"the dashed path was not searched: {result.stdout}"


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


#: Fenced shell, as a Markdown renderer would find it -- not as one exact
#: spelling. CommonMark allows whitespace between the fence and its info
#: string, and tilde fences as well as backticks, so a block written
#: ``` bash was invisible to a `\`\`\`bash` pattern while rendering, and being
#: pasted, exactly like the others.
def _canary_block() -> str:
    return next(t.content for t in _rendered_fences() if t.content.lstrip().startswith("# As it"))


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
    start = next(i for i, line in enumerate(lines) if _HEREDOC_OPEN in line)
    end = next(i for i, line in enumerate(lines) if i > start and line.strip() == "SQL")
    body = lines[start + 1 : end]
    # REJECTED, not stripped. The delimiter is quoted now, so the body is inert
    # shell -- but an earlier version had it unquoted AND discarded full-line
    # SQL comments before comparing, which let a comment carrying a command
    # substitution execute while being invisible to both whitelists. Nothing in
    # the heredoc is dropped from the comparison any more.
    assert not [line for line in body if line.strip().startswith("--")], (
        "the session block contains an SQL comment. The whitelist compares every "
        "line, so add it to _PERMITTED deliberately rather than letting the "
        "parser discard it."
    )

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
    "(SELECT count(*) FROM alembic_version WHERE version_num=:rev)=1 "
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


#: The shell around the heredoc, which decides what the SQL's output MEANS.
#: `_sql_statements` stops at the heredoc terminator, so without this the two
#: result checks could be deleted with all 63 tests green -- and they are the
#: mechanism that turns a missing completion marker or a busy checkpoint into a
#: failure.
_PERMITTED_SHELL = [
    # The assignment lines are IN the whitelist. An earlier version dropped any
    # line starting DB= or REV= before comparing, and separately replaced the
    # first of each before running -- so `DB=/path/to/tidewall.db; exit 0`
    # passed all 75 tests while making the published block exit 0 without ever
    # opening the database. A prefix is not authorisation to ignore a line.
    "DB=/path/to/tidewall.db",
    "REV=1b42ababed28",
    "out=$(sqlite3 \"$DB\" -cmd \".param set :rev '$REV'\" <<'SQL' 2>&1",
    ") || { printf 'the sequence stopped before completing:\\n%s\\n' \"$out\"; exit 1; }",
    "printf '%s\\n' \"$out\" | grep -qx 'SEQUENCE-COMPLETE' || { echo \"incomplete\"; exit 1; }",
    "[ \"$(printf '%s\\n' \"$out\" | grep -cx '0|0|0')\" -eq 2 ] || {",
    "printf 'a checkpoint did not complete:\\n%s\\n' \"$out\"; exit 1; }",
    "printf '%s\\n' \"$out\"",
]


def _shell_lines(block: str) -> list[str]:
    """The block's shell, with the heredoc body and comments removed."""
    lines = block.splitlines()
    start = next(i for i, line in enumerate(lines) if _HEREDOC_OPEN in line)
    end = next(i for i, line in enumerate(lines) if i > start and line.strip() == "SQL")
    outside = lines[:start] + [lines[start]] + lines[end + 1 :]
    kept = [line for line in outside if line.strip()]
    # Rejected, not skipped -- the SQL parser already refuses comments inside
    # the heredoc and the shell should match it. A comment-only line is
    # reader-visible: one added here made a false claim about the procedure
    # while every comparison stayed equal, because the comparison dropped it.
    assert not [line for line in kept if line.strip().startswith("#")], (
        "the session block's shell contains a comment. It is reader-visible, so "
        "add it to _PERMITTED_SHELL deliberately rather than letting the "
        "comparison discard it."
    )
    return [line.strip() for line in kept]


def test_the_session_block_shell_is_exactly_the_permitted_program():
    """The SQL whitelist proves the statements are there. This proves their
    results are checked."""
    assert _shell_lines(_extract("runbook:session")) == _PERMITTED_SHELL


def test_a_busy_checkpoint_makes_the_whole_block_fail(tmp_path):
    """The two-`0|0|0` check, bound dynamically as well as statically.

    A reader pinning WAL frames makes a checkpoint report busy. The SQL still
    runs to completion and prints `SEQUENCE-COMPLETE`; only the shell's row
    check turns that into a refusal. Delete it and this passes.
    """
    db = _head_db(tmp_path)
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE probe(x)")
    conn.commit()
    reader = sqlite3.connect(db)
    reader.execute("BEGIN")
    reader.execute("SELECT count(*) FROM probe").fetchall()
    conn.execute("INSERT INTO probe VALUES(1)")
    conn.commit()
    try:
        result = _run_session(db)
        assert result.returncode != 0, f"a busy checkpoint was accepted: {result.stdout}"
        assert "a checkpoint did not complete" in result.stdout
    finally:
        reader.close()
        conn.close()


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


def _head_db(tmp_path, page_size=None):
    """A WAL database at head, in two explicit stages.

    `alembic upgrade head` leaves the database in `delete` mode -- verified --
    and `get_engine` sets WAL from a *connect* listener, so constructing the
    engine is not enough. These are two operations and the fixture does both.
    """
    from app.db.engine import get_engine

    db = tmp_path / "head.db"
    if page_size is not None:
        # Before Alembic, and with a write, or it does nothing. SQLite ignores
        # PRAGMA page_size once the schema exists, and only persists it to the
        # header when the file is first written -- so setting it on an empty
        # connection and closing leaves the default. An earlier version of this
        # fixture set it after Alembic and ran all three "page sizes" against
        # one 4096-byte database.
        seed = sqlite3.connect(db)
        seed.execute(f"PRAGMA page_size={page_size}")
        seed.execute("VACUUM")
        seed.close()
    _alembic(db, "upgrade", "head")
    engine = get_engine(f"sqlite:///{db}")
    with engine.connect():
        pass
    engine.dispose()
    _assert_fixture_shape(db)
    if page_size is not None:
        conn = sqlite3.connect(db)
        try:
            actual = conn.execute("PRAGMA page_size").fetchone()[0]
        finally:
            conn.close()
        assert actual == page_size, f"asked for page_size {page_size}, got {actual}"
    return db


def _run_session(db, revision=HEAD_REVISION):
    """Run the published session block against `db`.

    Only the two assignment lines are replaced, and both must be found. The
    published block names a concrete database path and revision, so it is valid
    shell as printed; substituting them here points it at the fixture rather
    than at whatever the runbook happens to use as its example.
    """
    block = _substituted_session(db, revision)
    return subprocess.run(["bash", "-c", block], capture_output=True, text=True, cwd=REPO)


def _substituted_session(db, revision=HEAD_REVISION) -> str:
    """The published block with its two assignment templates filled in."""
    block = _extract("runbook:session")
    # Replace the EXACT published lines, not anything matching a prefix.
    # Substituting `^DB=.*$` silently swallows whatever else the line carried,
    # so a command appended to it would never be executed by a test and never
    # be seen by the whitelist.
    for published, replacement in (
        ("DB=/path/to/tidewall.db", f"DB={shlex.quote(str(db))}"),
        ("REV=1b42ababed28", f"REV={shlex.quote(revision)}"),
    ):
        assert f"\n{published}\n" in f"\n{block}", f"the published line {published!r} moved"
        block = block.replace(published, replacement, 1)
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


def _guard_line(label: str) -> int:
    """Which line of the heredoc a named guard is on.

    SQLite reports `Runtime error near line N`, and every guard shares one CHECK
    expression, so the line is the only thing distinguishing them -- and it is
    stable because the block is pinned byte for byte. Derived from the block so
    that reordering moves the expectation with it.
    """
    lines = _extract("runbook:session").splitlines()
    start = next(index for index, line in enumerate(lines) if _HEREDOC_OPEN in line)
    return next(
        number
        for number, line in enumerate(lines[start + 1 :], start=1)
        if f"INSERT INTO _assert SELECT '{label}'" in line
    )


#: Which guard each wrong-database fixture must be refused BY. Asserting only
#: "non-zero" lets a fixture be refused by the wrong guard -- and then the guard
#: it was written for could be deleted with the test still green.
#:
#: Row 6 drops `alembic_version`, so the revision statement fails to PARSE
#: rather than failing a CHECK -- it has its own test below. Row 11 drops
#: `interactions`, which an earlier version of this comment lumped in with it;
#: the type guard evaluates first and refuses at its own line, so it belongs
#: here like the rest.
_REFUSED_BY = {
    "1_journal_mode_delete": "journal mode is wal",
    "2_wrong_revision": "exactly one expected revision",
    "3_empty_alembic_version": "exactly one expected revision",
    "4_null_version_num": "exactly one expected revision",
    "5_more_than_one_revision_row": "exactly one expected revision",
    "7_legacy_input_messages": "interactions is the head shape",
    "8_legacy_output_messages": "interactions is the head shape",
    "9_legacy_detectors_json": "interactions is the head shape",
    "10_legacy_summary": "interactions is the head shape",
    # A one-column table is still a table, so the type guard passes it and
    # the shape guard is what refuses it.
    "11_interactions_dropped": "both are tables, not views",
    "12_interactions_one_column": "interactions is the head shape",
    "13_evidence_json_dropped": "interactions is the head shape",
    "14_interactions_counted_names_only": "interactions is the head shape",
    "15_contents_one_column": "interaction_contents is the head shape",
    "16_contents_counted_names_only": "interaction_contents is the head shape",
    "17_interactions_is_a_view": "both are tables, not views",
    "18_contents_is_a_view": "both are tables, not views",
    "19_contents_missing_id": "interaction_contents is the head shape",
    "20_contents_missing_policy_id": "interaction_contents is the head shape",
    "21_ordinary_column_renamed": "interactions is the head shape",
    "22_twenty_first_column": "interactions is the head shape",
    "23_virtual_generated_column": "interactions is the head shape",
    "24_stored_generated_column": "interaction_contents is the head shape",
    "25_drop_plus_add_same_total": "interactions is the head shape",
    "26_live_content_row": "no content rows remain",
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
    # Pinned, not searched. A search allows extra output beside the expected
    # rows -- an added statement's result, a warning, a second marker -- and an
    # operator keeps this output as their record of what happened.
    assert result.stdout == "0|0|0\n0|0|0\nSEQUENCE-COMPLETE\n", repr(result.stdout)
    assert result.stderr == "", repr(result.stderr)


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
    expected_guard = _REFUSED_BY.get(damage)
    if expected_guard is not None:
        assert f"near line {_guard_line(expected_guard)}:" in result.stdout, (
            f"{damage} should be refused by {expected_guard!r}, but something else "
            f"refused it: {result.stdout.strip()}"
        )


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
    """Silent on success, like the scan it calls."""
    result = _run_postclose(_clean_reclaimed_db(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == "", repr(result.stdout)
    assert result.stderr == "", repr(result.stderr)


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
    # Something the scan script would otherwise catch, so that a coarse
    # "non-zero" oracle cannot pass on the script's refusal instead of the
    # block's. Changing every `:?` to `:-` left the old form green.
    result = _run_postclose(db, **{variable: ""})
    assert result.returncode != 0
    assert variable in result.stderr, (
        f"the block did not refuse at its own ${{{variable}:?}} check: "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


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


def _plant_canary(db, representations):
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
    The page size is `_head_db`'s job, because it has to be set before Alembic
    creates the schema.
    """
    conn = sqlite3.connect(db)
    # Start from ON, so that turning it OFF is doing work. This build defaults
    # to OFF, so without this the OFF line below could be deleted with every
    # test still green -- while /usr/bin/sqlite3 on the same machine reports 2
    # (FAST), where the delete scrubs the WAL page image and the canary lands
    # only in the main file.
    conn.execute("PRAGMA secure_delete=ON")
    assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1
    conn.execute("PRAGMA secure_delete=OFF")
    assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 0
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

    db = _head_db(tmp_path, page_size=page_size)
    holder = _plant_canary(db, representations)
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


def test_the_changelog_links_to_the_runbook():
    """A Markdown link, not a pathname that happens to appear in prose.

    Checking only for the string passed when the link was replaced with plain
    text ending in the same path, which is the drift this gate exists to catch.
    """
    changelog = REPO / "CHANGELOG.md"
    text = changelog.read_text()
    targets = re.findall(r"\]\(([^)]+)\)", text)
    # Resolved, not suffix-matched. `missing/docs/operations/content-runbook.md`
    # ends with the expected path while pointing nowhere, and the separate
    # existence assertion was checking the real runbook rather than the target.
    resolved = {(changelog.parent / target).resolve() for target in targets}
    assert (
        RUNBOOK.resolve() in resolved
    ), f"no Markdown link resolving to the runbook; found {sorted(map(str, resolved))}"
    assert "destructive" in text.lower()


@pytest.mark.parametrize(
    "document",
    [RUNBOOK, REPO / "docs" / "operations" / "rehearsals" / "2026-08-20-migration-rehearsal.md"],
    ids=["runbook", "rehearsal"],
)
def test_every_relative_link_resolves(document):
    """Both documents, and at least one link somewhere.

    Iterating only the runbook was vacuous: it contains no relative links, so
    the loop never ran, and the rehearsal record's link to it could be broken
    with this test green.
    """
    targets = re.findall(r"\]\((?!https?:)([^)#]+)", document.read_text())
    for target in targets:
        assert (document.parent / target).resolve().exists(), f"{document.name}: {target}"


def test_the_rehearsal_record_links_to_the_runbook():
    """This link, to this artifact.

    "Some link that resolves" is satisfied by pointing it at the CHANGELOG,
    which is how the previous form stayed green while the rehearsal stopped
    referencing the runbook at all.
    """
    rehearsal = REPO / "docs" / "operations" / "rehearsals" / "2026-08-20-migration-rehearsal.md"
    targets = re.findall(r"\]\((?!https?:)([^)#]+)", rehearsal.read_text())
    resolved = {(rehearsal.parent / target).resolve() for target in targets}
    assert (
        RUNBOOK.resolve() in resolved
    ), f"the rehearsal record does not link to the runbook; found {sorted(map(str, resolved))}"


def test_the_published_shell_passes_shellcheck():
    """Over the substituted session block.

    The block is valid shell as published, so this would pass either way; it
    runs over the substituted form so that shellcheck sees the same program the
    dynamic tests execute.
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

    What it actually asserts: each of the four fields is present and neither
    empty nor marked outstanding. It cannot tell a considered value from an
    arbitrary one -- no test can -- so it is a gate against the table shipping
    as empty headings, which is what it was asked to prevent.
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


def test_the_worked_canary_examples_are_four_distinct_values():
    """Evaluated, not read.

    The first version of this example produced the same bytes for the plain and
    raw forms, so it demonstrated nothing about raw bytes while claiming to --
    an operator following it would pass the scan the same argument twice and
    conclude they had checked four representations.
    """
    block = re.search(r"```bash\n(# As it was written.*?)```", RUNBOOK.read_text(), re.S)
    assert block, "the worked canary example is gone"

    script = block.group(1) + (
        '\nprintf "%s\\0%s\\0%s\\0%s" ' '"$CANARY_PLAIN" "$CANARY_JSON" "$CANARY_UNICODE" "$CANARY_RAW"\n'
    )
    result = subprocess.run(["bash", "-c", script], capture_output=True)
    assert result.returncode == 0, result.stderr

    values = result.stdout.split(b"\0")
    #: The exact bytes each form must evaluate to, measured from the published
    #: block rather than guessed. Cardinality and distinctness are not enough:
    #: appending a non-breaking space to every assignment left four non-empty,
    #: distinct and WRONG values, and an operator scanning for those finds
    #: nothing while the real canary is still in the file.
    expected = [
        b'caf\xc3\xa9 "acct\\4111"',
        b'caf\xc3\xa9 \\"acct\\\\4111\\"',
        b'caf\\u00e9 \\"acct\\\\4111\\"',
        b'caf\xe9 "acct\\4111"',
    ]
    assert values == expected, [v.decode("utf-8", "backslashreplace") for v in values]


#: The post-close block's complete program. It had no whole-program gate at
#: all: its five inputs, two artifact checks and four scanner arguments were
#: each bound, and a standalone command inserted between them still ran for
#: every operator with all 76 tests green.
_PERMITTED_POSTCLOSE = [
    ': "${DB:?set DB to the database path}"',
    ': "${CANARY_PLAIN:?}" "${CANARY_JSON:?}" "${CANARY_UNICODE:?}" "${CANARY_RAW:?}"',
    'test ! -s "$DB-wal"     || { echo "WAL not truncated"; exit 1; }',
    'test ! -e "$DB-journal" || { echo "a rollback journal exists"; exit 1; }',
    './scripts/scan-artifacts.sh "$DB" "$CANARY_PLAIN" "$CANARY_JSON" \\',
    '"$CANARY_UNICODE" "$CANARY_RAW"',
]


def test_the_post_close_block_is_exactly_the_permitted_program():
    """The same treatment the session block gets.

    Binding each input and each argument separately is not the same as binding
    the program: nothing stopped an extra line being added between them.
    """
    # Comment lines included: they are reader-visible, and a comparison that
    # drops them accepts a false claim about the procedure.
    lines = [line.strip() for line in _extract("runbook:postclose").splitlines() if line.strip()]
    assert lines == _PERMITTED_POSTCLOSE


#: The worked canary example's complete program. Executing it and asserting its
#: four values is a semantic oracle, not a program gate: an extra command
#: inside it ran, and every test stayed green, because the values it produced
#: were still four distinct non-empty strings.
_PERMITTED_CANARY = [
    "# As it was written.",
    "CANARY_PLAIN='café \"acct\\4111\"'",
    "# As a JSON string value: the quotes and the backslash are escaped.",
    "CANARY_JSON='café \\\"acct\\\\4111\\\"'",
    "# As some writers encode non-ASCII: the é becomes a \\uXXXX escape. Writers",
    "# may also escape ASCII characters, so this form is worth searching for even",
    "# when your canary is plain -- it costs nothing if it is absent.",
    "CANARY_UNICODE='caf\\u00e9 \\\"acct\\\\4111\\\"'",
    "# The same characters under a DIFFERENT encoding -- here latin-1, where é is",
    "# the single byte 0xe9 rather than UTF-8's 0xc3 0xa9. This is the form to use",
    "# when the value may have been written by something that did not agree with",
    "# your database about encoding. If everything in the path was UTF-8, this is",
    "# byte-for-byte the plain form.",
    "CANARY_RAW=$'caf\\xe9 \"acct\\\\4111\"'",
]


def test_the_worked_canary_block_is_exactly_the_permitted_program():
    """Four assignments and nothing else."""
    # Comments included. They are not decoration here: each one tells the
    # operator what that representation is for, and rewriting one to say a form
    # is optional changed what an operator would do while every gate stayed
    # green.
    # NOT stripped. A non-breaking space appended outside the closing quote of
    # each assignment is erased by Python's strip() -- U+00A0 is whitespace to
    # str.strip() -- while bash concatenates it to the value. The four canaries
    # then differ from the operator's actual data by an invisible character,
    # the scan finds nothing, and a clean result means the opposite of what it
    # says. Physical lines, compared as they are.
    lines = [line for line in _canary_block().splitlines() if line.strip()]
    assert lines == _PERMITTED_CANARY


def _rendered(document=None):
    """What a CommonMark renderer sees.

    Four hand-rolled patterns tried to answer this and each was defeated by a
    form a renderer accepts: a fence with whitespace before its info string, a
    fence indented three spaces, a fence inside nested block quotes with legal
    internal spacing, and a heading inside a block quote or list item. The
    question these gates ask is "what does a reader see?", and that is a
    question for a parser.
    """
    from markdown_it import MarkdownIt

    return MarkdownIt("commonmark").parse((document or RUNBOOK).read_text())


def _rendered_fences(document=None):
    return [t for t in _rendered(document) if t.type == "fence"]


def _rendered_headings(document=None):
    tokens = _rendered(document)
    # `token.level` is the container nesting depth. Without it, moving a
    # declared section into a block quote or a list item leaves the (tag, text)
    # pair identical while a renderer presents it as quoted or nested material
    # rather than as a step of the procedure.
    return [
        (token.level, token.tag, tokens[index + 1].content)
        for index, token in enumerate(tokens)
        if token.type == "heading_open"
    ]


#: The runbook's headings as RENDERED, in order. Pinned because an operator
#: step can be added as prose with an inline command -- no fence, no HTML --
#: and the demonstrated bypass was a whole new step, not an inline span.
#:
#: A regex over `^#` counted 29 of these, because it also counted the shell
#: comments inside the fenced blocks. The parser sees 19.
_HEADINGS = [
    (0, "h1", "Reclaiming deleted content"),
    (0, "h2", "1. Upgrading to this release is destructive"),
    (0, "h2", "2. Reclaiming the space"),
    (0, "h3", "Before you start"),
    (0, "h3", "Why the heredoc is quoted"),
    (0, "h3", "Why two checkpoints"),
    (0, "h3", "Reading the result"),
    (0, "h3", "After the session has closed"),
    (0, "h2", "3. What this does, and what it does not"),
    (0, "h2", "4. Where the bytes may still be"),
    (0, "h2", "5. Backup and snapshot disposition"),
    (0, "h2", "6. Where content crosses the network"),
    (0, "h2", "7. Retention"),
    (0, "h2", "8. Grants"),
    (0, "h2", "9. Export targets"),
    (0, "h2", "10. One live server per database"),
    (0, "h2", "11. Export attempts that did not resolve"),
    (0, "h2", "12. A deployment requirement: NAT64"),
    (0, "h2", "Deviations from the accepted design"),
]


def test_the_runbook_renders_exactly_the_declared_sections():
    """Headings as a reader sees them, wherever they are nested."""
    assert _rendered_headings() == _HEADINGS


def test_the_rendered_code_blocks_are_exactly_the_three_gated_ones():
    """An ordered inventory, not a membership test.

    Membership establishes that nothing unknown appears. It does not establish
    that there are three, that each appears once, that they appear in the order
    the procedure runs, or that they are tagged the way a renderer expects --
    and each of those was demonstrably exploitable:

    * an exact copy of the post-close verifier placed BEFORE the session shows
      an operator the verification before the operation it verifies;
    * a copy of the worked example tagged `mermaid` renders as a diagram on
      GitHub, so identical content is not identical to what a reader sees.
    """
    expected = [
        ("bash", _extract("runbook:session")),
        ("bash", _canary_block()),
        ("bash", _extract("runbook:postclose")),
    ]
    assert [(token.info, token.content) for token in _rendered_fences()] == expected


def test_the_runbook_renders_no_indented_code_block():
    """Indented code renders as something to paste and has no fence to count."""
    indented = [t.content for t in _rendered() if t.type == "code_block"]
    assert not indented, "indented code blocks:\n" + "\n---\n".join(indented)


def test_the_runbook_renders_no_html_but_its_two_markers():
    """Raw HTML renders. A `<pre>` block reads exactly like a fenced one."""
    html = [t.content.strip() for t in _rendered() if t.type in ("html_block", "html_inline")]
    unexpected = [h for h in html if not re.fullmatch(r"<!-- runbook:(?:session|postclose) -->", h)]
    assert not unexpected, "raw HTML in the runbook:\n" + "\n".join(unexpected)


@pytest.mark.parametrize(
    "path",
    [
        "docs/operations/content-runbook.md",
        "scripts/scan-artifacts.sh",
        "docs/operations/rehearsals/2026-08-20-migration-rehearsal.md",
    ],
)
def test_no_invisible_characters_anywhere_in_the_published_artifacts(path):
    """Invisible characters change what an operator runs and not what they read.

    A non-breaking space appended outside a closing quote in the worked example
    passed every gate here while corrupting all four canaries: bash concatenated
    it, Python's strip() erased it, and the resulting scan reported clean for
    content that was still present. That specific case is now bound by comparing
    physical lines, but the class is wider than one character in one block --
    prose that tells an operator what to type is just as reachable, and so is
    the script.

    Permitted non-ASCII is enumerated rather than allowed by category: `é` is in
    the worked example deliberately, because an all-ASCII canary cannot
    demonstrate the difference between the four representations.
    """
    permitted = {"§", "é", "—"}
    text = (REPO / path).read_text()
    offenders = sorted(
        {
            character
            for character in text
            if ord(character) > 127
            and character not in permitted
            or (unicodedata.category(character) in ("Cf", "Cc", "Zs", "Zl", "Zp") and character not in " \n\t")
        }
    )
    assert not offenders, f"{path} contains {[hex(ord(c)) for c in offenders]}"


def test_the_scan_says_exactly_what_it_found_and_nothing_else(tmp_path):
    """The complete diagnostic, not a substring of it.

    Two things this binds that a status-and-substring oracle does not:

    * the message can be negated -- "NOT FOUND in ..." keeps exit 1 and the
      substring the old tests looked for, so an operator reads that the canary
      was absent from a scan that found it;
    * the match itself must never be printed. Quiet matching is the only thing
      stopping the search from echoing the line it matched, which would copy
      deleted prompt text into a terminal, a CI log, or the rehearsal record --
      from the tool whose whole purpose is confirming that text is gone.
    """
    db = tmp_path / "t.db"
    _sqlite_file(db, "nothing interesting")
    shm = tmp_path / "t.db-shm"
    shm.write_text(f"prefix {CANARY} suffix")

    result = _run_scan(db, CANARY)
    assert result.returncode == 1
    assert result.stdout == f"FOUND in {shm}\n", repr(result.stdout)
    assert result.stderr == "", repr(result.stderr)
    assert CANARY not in result.stdout + result.stderr, "the scan echoed the match"
    assert "prefix" not in result.stdout + result.stderr, "the scan echoed the matched line"


def test_a_clean_scan_says_nothing(tmp_path):
    db = tmp_path / "t.db"
    _sqlite_file(db, "nothing interesting")
    result = _run_scan(db, CANARY)
    assert result.returncode == 0
    assert result.stdout == "" and result.stderr == "", (result.stdout, result.stderr)


def test_the_scan_searches_bytes_not_characters(tmp_path):
    """The published worked example's raw form is a Latin-1 byte.

    Without the script's own byte-locale override, an inherited UTF-8 locale
    makes the search reject that byte as illegal and return "could not scan"
    for a canary that is present. The suite evaluated the raw value and
    exercised the scanner, but never passed one through the other.
    """
    db = tmp_path / "t.db"
    _sqlite_file(db, "nothing interesting")
    raw = b'caf\xe9 "acct\\4111"'
    (tmp_path / "t.db-shm").write_bytes(b"padding " + raw + b" padding")

    # Passed as BYTES. A str is re-encoded as UTF-8 on the way to argv, so the
    # argument would be caf\xc3\xa9 and would not match the caf\xe9 in the file:
    # the test would report "not found" for a canary it never searched for.
    utf8_env = {**os.environ, "LC_ALL": "en_US.UTF-8", "LANG": "en_US.UTF-8"}

    def run(canary):
        return subprocess.run(
            [str(SCAN).encode(), str(db).encode(), canary],
            capture_output=True,
            cwd=REPO,
            env=utf8_env,
        )

    present = run(raw)
    assert present.returncode == 1, (present.returncode, present.stdout, present.stderr)

    absent = run(b"caf\xe9 absent")
    assert absent.returncode == 0, (absent.returncode, absent.stdout, absent.stderr)


def test_every_could_not_scan_path_says_so_exactly(tmp_path):
    """The exit-2 diagnostics, pinned like the others.

    An operator running this by hand reads the message; they are not guaranteed
    to check `$?` afterwards. So a "could not scan" path that prints something
    reassuring contradicts the three-status contract even though its status is
    right -- and changing the missing-canary message to claim the scan was
    clean left every test green.

    Both streams. An earlier version pinned only stdout and left the search
    tool's stderr through on the unreadable case, on the grounds that its
    wording differs between platforms -- which made the contract unpinnable,
    and an unpinnable contract is one a reassuring sentence can be added to.
    The script now discards the tool's stderr and says everything itself.
    """
    db = tmp_path / "t.db"
    _sqlite_file(db, "nothing interesting")

    def refusal(*canaries, database=db):
        result = _run_scan(database, *canaries)
        assert result.returncode == 2, result
        assert result.stderr == "", repr(result.stderr)
        return result.stdout

    assert refusal() == "no canary supplied\n"
    assert refusal("") == "empty canary supplied\n"
    assert refusal(CANARY, "", "other") == "empty canary supplied\n"

    missing = tmp_path / "absent.db"
    assert refusal(CANARY, database=missing) == f"no database at {missing}\n"

    unreadable = tmp_path / "t.db-shm"
    unreadable.mkdir()
    result = _run_scan(db, CANARY)
    assert result.returncode == 2
    assert result.stdout == f"scan FAILED on {unreadable} (grep exit 2)\n", repr(result.stdout)
    assert result.stderr == "", repr(result.stderr)


def test_a_missing_alembic_version_table_fails_to_parse(tmp_path):
    """The one fixture that is not a CHECK refusal.

    With `alembic_version` gone the revision statement cannot be prepared, so
    SQLite reports a parse error rather than a failed constraint. Asserted
    separately rather than folded in with the CHECK refusals, because calling
    them the same thing is what let fixture 11 sit unmapped.
    """
    db = _head_db(tmp_path)
    _DAMAGE["6_no_alembic_version_table"](db)
    result = _run_session(db)
    assert result.returncode != 0
    assert "no such table: alembic_version" in result.stdout, result.stdout


#: The destructive warning, complete. Not required substrings plus a list of
#: forbidden words: prose contradicts itself in unbounded ways, and a list of
#: synonyms is a gate whose boundary nobody can state. This is the sentence an
#: operator reads when deciding whether to take a backup they will otherwise
#: never be able to recover, so it is compared whole.
_CHANGELOG_WARNING = (
    "### Upgrading — this release is destructive\n"
    "\n"
    "Upgrading deletes every row in `interactions` and drops four columns that held\n"
    "prompt content. There is no data rollback in either direction: `alembic\n"
    "downgrade` restores the schema, not the data. Take a backup first, and read\n"
    "[the content runbook](docs/operations/content-runbook.md) before upgrading —\n"
    "it covers the destructive migration, reclaiming the space the deleted content\n"
    "still occupies on disk, and what that reclamation does and does not achieve.\n"
)[:-1]


def test_the_changelog_warning_is_exactly_the_declared_text():
    changelog = (REPO / "CHANGELOG.md").read_text()
    start = changelog.index("### Upgrading")
    # To the end of the section, not the length of the expected text -- a prefix
    # comparison accepts anything appended after it, inside the same warning.
    end = changelog.index("\n### ", start + 5)
    assert changelog[start:end].rstrip() == _CHANGELOG_WARNING


#: Every row of the rehearsal record's two tables, by label. Searching the
#: document for phrases left rows unbound individually -- the post-close row
#: could be changed to say the scan found all four representations while
#: keeping its successful exit, which is a state the published program cannot
#: produce, and nothing noticed.
_REHEARSAL_ROWS = {
    "step": "result",
    "Migrated to `d5a71f3c8e02`, the migration's predecessor": "all four legacy columns present",
    "Planted a canary in the legacy content columns": "four representations",
    "Froze a copy as the backup": "see the hashes below",
    "Confirmed all four representations are in the frozen backup": "all four found",
    "Upgraded to head `1b42ababed28`": "migration succeeded",
    "Ran the runbook's session block": "exit 0; `0\\|0\\|0`, `0\\|0\\|0`, `SEQUENCE-COMPLETE`",
    "Ran the runbook's post-close block": "exit 0; no representation found in the database, WAL or SHM",
    "Reclaimed database": "see the hashes below",
    "field": "value",
    "Backup identifiers": "Rehearsal copy; see the frozen-backup hash above",
    "Owner": "Tidewall maintainers (rehearsal artifact; no production backup taken)",
    "Retention or deletion disposition": (
        "Discarded with the rehearsal's temporary directory; no production backup involved"
    ),
    "Date": "2026-08-20",
}


def test_the_rehearsal_record_rows_are_exactly_the_declared_evidence():
    """Each row's value, by its label.

    A record whose rows contradict the procedure is not evidence of it. This
    cannot prove the historical run happened; it does stop the record from
    describing a run the published program could not have produced.
    """
    # An ordered list of pairs, not a dict: dict() silently keeps the last of
    # any duplicated label, so a second contradicting row with the same label
    # disappears from the comparison entirely.
    pairs = [
        (key, value)
        for key, value in re.findall(r"(?m)^\|\s*(.+?)\s*\|\s*(.+?)\s*\|$", REHEARSAL.read_text())
        if not set(key) <= set("-: ")
    ]
    assert pairs == list(_REHEARSAL_ROWS.items())

    # The disposition fields must still be filled in, not merely present.
    for field in ("Backup identifiers", "Owner", "Retention or deletion disposition", "Date"):
        assert _REHEARSAL_ROWS[field] and "OUTSTANDING" not in _REHEARSAL_ROWS[field]

    # Bound to their labels, not counted. Two hashes somewhere in the document
    # says nothing about which artifact each describes.
    # Each digest by VALUE, not by shape. Requiring "some 64-character hex
    # string after this label" leaves the two interchangeable: swapping the
    # frozen backup's digest with the reclaimed database's passed, which would
    # have the record attest that the artifact before cleanup is the one after.
    expected_digests = {
        "frozen backup": "a6629d032d2071f2fb36bf7617930432aaa6ab5cd73ca6a0cc2eca5357b26230",
        "reclaimed database": "e631231124de2d244d0b3e47b117b8ba472ebf97b6aff6d5ee0ea31db840f358",
    }
    lines = REHEARSAL.read_text().splitlines()
    for label, digest in expected_digests.items():
        index = next(i for i, text in enumerate(lines) if text.startswith(f"- {label}:"))
        assert lines[index + 1].strip() == f"`{digest}`", (label, lines[index + 1])


#: The two sections that ARE the honesty boundary, compared whole.
#:
#: Everything else in the runbook is explanatory prose, and a reviewer reading
#: a diff is the check on it. These two are different in kind: they are the
#: sentences that say what the procedure does NOT do -- what it cannot promise,
#: and where the bytes may still be. They are what an operator would repeat to
#: a regulator, and softening one is invisible in a suite that samples phrases.
#:
#: ~15k characters of this document are not compared by any test. That is a
#: deliberate line, drawn here rather than left unstated: a full-text pin over
#: prose becomes a checksum people update reflexively, which is a gate that
#: looks like coverage.
_HONESTY_SECTIONS = {
    "## 3. What this does, and what it does not": (
        "## 3. What this does, and what it does not\n"
        "\n"
        "**It deletes nothing.** `VACUUM` compacts pages that are already free. If the\n"
        "content you have in mind is still live, it is faithfully preserved and the\n"
        "command still succeeds. That is why the preconditions above exist: a run\n"
        "against an unmigrated database, the wrong copy, or a database that still holds\n"
        "content **fails** rather than succeeding while reclaiming nothing.\n"
        "\n"
        "**A zero exit means the sequence and its checks completed.** It does not mean\n"
        "any byte was reclaimed. Running it twice exits zero the second time with the\n"
        "file unchanged.\n"
        "\n"
        "**This procedure is for the destructive migration only.** It requires that no\n"
        "content rows remain, because that is the only state in which the claim it\n"
        "supports is checkable. After a routine retention purge, with in-policy content\n"
        'still live, no scan of the resulting files can distinguish "the expired rows\n'
        'are gone" from "the expired rows were never there".\n'
        "\n"
        "Reclaiming space after routine purges is not supported yet. It needs a way for\n"
        "an operator to state the deletion boundary they mean and for the procedure to\n"
        "check it. That is open work, recorded as the open question in §9 of\n"
        "`internal/reviews/2026-08-19-p006-step9-design-v10.md`.\n"
    ),
    "## 4. Where the bytes may still be": (
        "## 4. Where the bytes may still be\n"
        "\n"
        "Live and untouched in this same database:\n"
        "\n"
        "- content still within its retention period;\n"
        "- the content-access audit, which deliberately outlives what it describes;\n"
        "- export attempts, with their interaction, key, policy and target identifiers,\n"
        "  destination host and addresses, payload size and outcome;\n"
        "- reconciliation rows, whose `evidence` field is operator-supplied text that\n"
        "  nothing stops an operator pasting prompt content into;\n"
        "- `activity_log.old_value` and `new_value`, which are generic JSON sinks;\n"
        "- control-plane configuration — prompt-list patterns, detector settings, export\n"
        "  target URLs and headers;\n"
        "- the vault, which is outside this procedure entirely.\n"
        "\n"
        "Outside this database:\n"
        "\n"
        "- backups and filesystem or volume snapshots;\n"
        "- replicas;\n"
        "- **the transient database `VACUUM` creates**, which is as large as the\n"
        "  original and contains the whole logical database. It may be written outside\n"
        "  the database directory, under `SQLITE_TMPDIR`, `TMPDIR`, `/var/tmp`,\n"
        "  `/usr/tmp`, `/tmp`, or the working directory;\n"
        "- filesystem journals and copy-on-write layers;\n"
        "- swap and hibernation images; crash dumps; the page cache;\n"
        "- SSD free space, until it is overwritten;\n"
        "- every system a record was exported to.\n"
        "\n"
        "The claim this procedure supports is exactly: *after a successful sequence, the\n"
        "supplied representations of your canary were not found in the database, WAL and\n"
        "SHM files.* That is not media sanitisation, and it is not a statement about any\n"
        "of the above.\n"
    ),
}


@pytest.mark.parametrize("heading", sorted(_HONESTY_SECTIONS))
def test_the_honesty_boundary_sections_are_exactly_as_declared(heading):
    text = RUNBOOK.read_text()
    start = text.index(heading)
    end = text.index("\n## ", start + 5)
    assert text[start:end] == _HONESTY_SECTIONS[heading]


#: The scanner's complete source. Its behaviour is covered by two dozen cases,
#: which is not the same as binding the program: an operation appended after
#: the scan ran against every fixture database with all tests green, and an
#: operator would have run it too.
#:
#: The three runbook blocks are pinned because they live in a Markdown file
#: where a change is easy to miss. This is pinned for the same reason in
#: reverse -- it is a file a reviewer reads as code, and the thing that makes it
#: dangerous is that operators paste its invocation without reading it at all.
_PERMITTED_SCRIPT = (
    "#!/usr/bin/env bash\n"
    "# scan-artifacts.sh DB CANARY [CANARY...]\n"
    "#\n"
    "# Search a SQLite database and its sidecars for byte sequences that should no\n"
    "# longer be recoverable from them.\n"
    "#\n"
    "#   0 - scanned every present artifact, nothing found\n"
    "#   1 - found\n"
    "#   2 - could not scan; NOT a clean result\n"
    "#\n"
    '# Exit 2 is deliberately distinct from 0. "The scan did not happen" must never\n'
    '# be read as "nothing was found", which is the whole reason this is a script\n'
    "# with three statuses rather than a loop with a boolean.\n"
    'DB="$1"; shift\n'
    "\n"
    "# Validated BEFORE the file loop. With these checks inside it, a run with no\n"
    "# artifacts present skipped every iteration and reported clean.\n"
    '[ "$#" -gt 0 ] || { echo "no canary supplied"; exit 2; }\n'
    'for c in "$@"; do\n'
    '  [ -n "$c" ] || { echo "empty canary supplied"; exit 2; }\n'
    "done\n"
    '[ -e "$DB" ] || { echo "no database at $DB"; exit 2; }\n'
    "\n"
    "found=0\n"
    "scanned=0\n"
    'for f in "$DB" "$DB-wal" "$DB-shm"; do\n'
    '  [ -e "$f" ] || continue\n'
    '  for c in "$@"; do\n'
    "    # -F: a canary is a literal, not a pattern. Without it a canary of '.*'\n"
    "    # reports a find for a string that is absent.\n"
    "    # The search tool's own stderr is discarded: its wording differs between\n"
    "    # platforms, so leaving it through makes this script's output contract\n"
    "    # unpinnable -- and an unpinnable contract is one a reassuring sentence can\n"
    "    # be added to. Everything an operator needs is in our own message below:\n"
    "    # which artifact, and the tool's exit status.\n"
    '    LC_ALL=C grep -qaF -e "$c" -- "$f" 2>/dev/null; rc=$?\n'
    '    case "$rc" in\n'
    '      0) echo "FOUND in $f"; found=1 ;;\n'
    "      1) : ;;\n"
    '      *) echo "scan FAILED on $f (grep exit $rc)"; exit 2 ;;\n'
    "    esac\n"
    "  done\n"
    "  scanned=$((scanned+1))\n"
    "done\n"
    "\n"
    "# Unreachable on a stable filesystem -- the database check above fires first --\n"
    "# and kept for the case where an artifact disappears between that check and\n"
    "# this loop. No test binds it, and the test module says so.\n"
    '[ "$scanned" -gt 0 ] || { echo "scanned nothing"; exit 2; }\n'
    'exit "$found"\n'
)


def test_the_scan_script_is_exactly_the_permitted_program():
    assert SCAN.read_text() == "".join(_PERMITTED_SCRIPT)
