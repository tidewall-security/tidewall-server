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
