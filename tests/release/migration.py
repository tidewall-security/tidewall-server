"""The migration fixture: what a stored value survives an upgrade as.

A migration is where a value that was correctly stored yesterday becomes a
value nobody is looking at today. The fixture has to establish five things,
and the third is the one that is normally assumed:

  1. AN ASSERTED LEGACY REVISION -- not "some old schema", a named one. A
     fixture that seeds whatever the current models produce is testing the
     migration against its own output.
  2. COMPLETE LEGACY SEEDING -- every column the legacy schema has. Seeding
     the columns the new code reads proves the new code reads them.
  3. PRE-MIGRATION PHYSICAL-PRESENCE PROOF -- the canary's bytes are IN THE
     FILE before the upgrade runs. Without it, "absent afterwards" is equally
     true of a value that was never written, and that is a passing test which
     measures the seeding, not the migration.
  4. THE EXACT OPERATOR SEQUENCE -- the commands an operator actually runs, in
     order. A fixture that calls the migration functions directly skips
     whatever the runner does around them.
  5. ARTIFACT IDENTITY AND BYTE COUNTS ESTABLISHED INDEPENDENTLY OF THE
     SCANNER -- read off the files, not reported by the thing under test.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


class PhysicalPresenceNotEstablished(Exception):
    """The canary was not in the file before the migration ran."""


class MigrationSequenceFailed(Exception):
    """An operator step exited non-zero."""


@dataclass(frozen=True)
class ArtifactCensus:
    """Paths and byte counts, read off the filesystem.

    Independent of the scanner: nothing under test contributes a number here.
    """

    entries: dict[str, int]

    @classmethod
    def of(cls, db: Path) -> ArtifactCensus:
        found: dict[str, int] = {}
        for suffix in ("", "-wal", "-shm", "-journal"):
            candidate = Path(str(db) + suffix)
            if candidate.exists():
                found[candidate.name] = candidate.stat().st_size
        return cls(entries=found)

    def occurrences(self, db: Path, needle: bytes) -> dict[str, int]:
        out = {}
        for name in self.entries:
            path = db.parent / name
            out[name] = path.read_bytes().count(needle)
        return out


def assert_physical_presence(db: Path, needle: bytes) -> dict[str, int]:
    """Prove the canary is ON DISK before the migration.

    Returns the per-artifact counts so the post-migration comparison is
    against a measured number rather than an assumed one.
    """
    census = ArtifactCensus.of(db)
    counts = census.occurrences(db, needle)
    if sum(counts.values()) == 0:
        raise PhysicalPresenceNotEstablished(
            "the canary is not in any artifact before the migration, so its "
            "absence afterwards would prove nothing about the migration"
        )
    return counts


def run_operator_sequence(steps: list[list[str]], cwd: Path, env: dict) -> list[str]:
    """Run the operator's own commands, in order, and refuse on any failure.

    A step that fails and is ignored produces a database that never migrated,
    and every later assertion then describes the legacy schema.
    """
    outputs = []
    for step in steps:
        result = subprocess.run(step, cwd=cwd, env=env, capture_output=True, text=True)
        if result.returncode != 0:
            raise MigrationSequenceFailed(
                f"{' '.join(step)} exited {result.returncode}: " f"{(result.stderr or result.stdout).strip()[:400]}"
            )
        outputs.append(result.stdout)
    return outputs


def stamped_revision(db: Path) -> str | None:
    """The revision the database claims, read from alembic_version."""
    import sqlite3

    conn = sqlite3.connect(db)
    try:
        row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'").fetchone()
        if row is None:
            return None
        version = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        return version[0] if version else None
    finally:
        conn.close()
