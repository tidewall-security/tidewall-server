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

import pathlib
import re
import sqlite3
import subprocess

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
            statements.append("\n".join(buffer))
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
