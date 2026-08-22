"""The migration fixture, run through the operator's own commands."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from tests.release.migration import (
    ArtifactCensus,
    MigrationSequenceFailed,
    PhysicalPresenceNotEstablished,
    assert_physical_presence,
    run_operator_sequence,
    stamped_revision,
)

CANARY = b"CANARY-MIGRATION-4d72"

#: The revision the fixture seeds AS. Asserted, not inferred: a fixture that
#: seeds whatever the current models produce tests the migration against its
#: own output.
LEGACY_REVISION = "f1ab8c9e9974"

REPO = Path(__file__).resolve().parents[2]


def _legacy_database(tmp_path: Path) -> Path:
    """A database at the asserted legacy revision, seeded completely."""
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
    conn.execute("INSERT INTO alembic_version VALUES (?)", (LEGACY_REVISION,))
    # Every column the legacy table has, not only the ones new code reads.
    conn.execute(
        "CREATE TABLE legacy_records ("
        "  id INTEGER PRIMARY KEY,"
        "  name TEXT NOT NULL,"
        "  payload TEXT,"
        "  note TEXT,"
        "  created_at TEXT"
        ")"
    )
    conn.execute(
        "INSERT INTO legacy_records(id, name, payload, note, created_at) " "VALUES (1, ?, ?, ?, ?)",
        ("policy-one", CANARY.decode(), "a note", "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    conn.close()
    return db


# --- the asserted revision --------------------------------------------------


def test_the_fixture_seeds_a_named_legacy_revision(tmp_path: Path):
    db = _legacy_database(tmp_path)
    assert stamped_revision(db) == LEGACY_REVISION


def test_the_legacy_revision_exists_in_the_repository():
    """A fixture pinned to a revision nobody has is pinned to nothing."""
    versions = REPO / "alembic" / "versions"
    assert versions.is_dir(), versions
    stems = {p.name.split("_", 1)[0] for p in versions.glob("*.py")}
    assert LEGACY_REVISION in stems, sorted(stems)[:8]


def test_the_legacy_revision_is_not_the_current_head():
    """Otherwise the fixture migrates nothing and passes."""
    import subprocess

    result = subprocess.run(["uv", "run", "alembic", "heads"], cwd=REPO, capture_output=True, text=True)
    head = result.stdout.split()[0] if result.stdout.split() else ""
    assert head, result.stderr[:200]
    assert head != LEGACY_REVISION, f"the fixture seeds the head revision {head}, so no migration runs"


# --- pre-migration physical presence ----------------------------------------


def test_physical_presence_is_established_before_the_migration(tmp_path: Path):
    """The proof that makes a later absence mean something."""
    db = _legacy_database(tmp_path)
    counts = assert_physical_presence(db, CANARY)
    assert sum(counts.values()) > 0
    assert any(k.endswith(("legacy.db", "legacy.db-wal")) for k in counts), counts


def test_a_canary_that_was_never_written_is_refused(tmp_path: Path):
    """The failing shape this guard exists for: a fixture that seeded nothing
    passes every post-migration absence assertion."""
    db = _legacy_database(tmp_path)
    with pytest.raises(PhysicalPresenceNotEstablished, match="prove nothing"):
        assert_physical_presence(db, b"NEVER-WRITTEN-ANYWHERE-8a31")


# --- the exact operator sequence --------------------------------------------


def test_the_operator_sequence_runs_the_real_commands(tmp_path: Path):
    """Not the migration functions directly.

    Calling them directly skips whatever the runner does around them, which
    is where the version stamp and the transaction boundary live.
    """
    db = _legacy_database(tmp_path)
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{db}"}

    outputs = run_operator_sequence([["uv", "run", "alembic", "current"]], cwd=REPO, env=env)
    assert outputs, "no operator step ran"


def test_a_failing_operator_step_is_refused_not_ignored(tmp_path: Path):
    """A step that fails silently leaves a database that never migrated, and
    every later assertion then describes the legacy schema."""
    with pytest.raises(MigrationSequenceFailed, match="exited"):
        run_operator_sequence(
            [["uv", "run", "alembic", "upgrade", "no-such-revision"]],
            cwd=REPO,
            env={**os.environ},
        )


# --- artifact identity and byte counts, independent of the scanner ----------


def test_the_census_is_read_off_the_filesystem(tmp_path: Path):
    """Nothing under test contributes a number here."""
    db = _legacy_database(tmp_path)
    census = ArtifactCensus.of(db)

    assert census.entries, "no artifact was censused"
    for name, size in census.entries.items():
        assert size == (db.parent / name).stat().st_size


def test_the_census_covers_the_sidecars_not_only_the_main_file(tmp_path: Path):
    db = _legacy_database(tmp_path)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("INSERT INTO legacy_records(id, name) VALUES (2, 'second')")
    conn.commit()

    census = ArtifactCensus.of(db)
    assert any(name.endswith("-wal") for name in census.entries), census.entries
    conn.close()


def test_the_census_counts_bytes_per_artifact(tmp_path: Path):
    db = _legacy_database(tmp_path)
    census = ArtifactCensus.of(db)
    counts = census.occurrences(db, CANARY)

    assert set(counts) == set(census.entries)
    assert sum(counts.values()) >= 1
