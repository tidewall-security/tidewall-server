"""What the sweep actually reads, and when it reads it.

Three facts drive every decision here, each established by a counterexample
rather than by reasoning:

**A logical scan is not a byte scan.** A row inserted and deleted inside one
operation leaves no trace in a before/after query and its bytes remain on disk.

**An after-close scan destroys the evidence.** Closing the last connection
checkpoints the latest page image and removes the WAL; with `secure_delete` on,
the latest page carries no canary. A committed WAL frame that physically held
the value is gone by the time anything looks. Measured: one occurrence in the
WAL before close, none anywhere after.

**Byte presence is not an occurrence path.** Finding a value in a file says it
reached disk, not which column holds it. Attribution comes from the statement
trace plus the copy and cascade maps, and the schema invariant is what makes
that attribution exhaustive.
"""

from __future__ import annotations

import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Artifact:
    """One captured file, with the moment it was taken."""

    path: Path
    kind: str  # "db" | "wal" | "shm" | "journal"
    moment: str  # "in-flight" | "post-close"

    @property
    def data(self) -> bytes:
        return self.path.read_bytes() if self.path.exists() else b""


@dataclass
class ArtifactSet:
    """Every artifact belonging to one database, across both moments."""

    artifacts: list[Artifact] = field(default_factory=list)

    def bytes_at(self, moment: str) -> dict[str, bytes]:
        return {a.kind: a.data for a in self.artifacts if a.moment == moment}

    def occurrences(self, needle: bytes, moment: str | None = None) -> dict[str, int]:
        """How many times *needle* appears in each artifact."""
        out: dict[str, int] = {}
        for artifact in self.artifacts:
            if moment is not None and artifact.moment != moment:
                continue
            data = artifact.data
            if data:
                out[f"{artifact.moment}:{artifact.kind}"] = data.count(needle)
        return out


#: The sidecars a SQLite database can carry. The rollback journal and WAL of
#: the database UNDER TEST are in the corpus -- they are produced by the
#: operation being measured. Temporary files and other databases are not.
SIDECARS: tuple[tuple[str, str], ...] = (
    ("db", ""),
    ("wal", "-wal"),
    ("shm", "-shm"),
    ("journal", "-journal"),
)


def capture_in_flight(db: Path, into: Path, label: str = "in-flight") -> ArtifactSet:
    """Copy every artifact WHILE the database is open.

    A reader must be held open by the caller across this call, or SQLite may
    checkpoint and remove the WAL between statements -- taking with it the
    frames this exists to read. `capture_with_reader` does that correctly.
    """
    into.mkdir(parents=True, exist_ok=True)
    captured = ArtifactSet()
    for kind, suffix in SIDECARS:
        source = Path(str(db) + suffix)
        if not source.exists():
            continue
        target = into / f"{label}-{kind}"
        shutil.copyfile(source, target)
        captured.artifacts.append(Artifact(target, kind, label))
    return captured


class capture_with_reader:
    """Hold a snapshot open so the WAL survives long enough to be copied.

    An open read transaction pins the WAL: SQLite cannot checkpoint frames a
    reader might still need. Without it, a capture racing an autocheckpoint
    reads a WAL that has already been truncated, and reports absence for a
    value that was there.
    """

    def __init__(self, db: Path) -> None:
        self._db = db
        self._conn: sqlite3.Connection | None = None

    def __enter__(self) -> capture_with_reader:
        self._conn = sqlite3.connect(self._db)
        self._conn.execute("BEGIN")
        # Touch the schema so the transaction genuinely holds a snapshot; a
        # BEGIN with no read does not pin anything.
        self._conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return self

    def capture(self, into: Path, label: str = "in-flight") -> ArtifactSet:
        return capture_in_flight(self._db, into, label)

    def __exit__(self, *exc: object) -> None:
        if self._conn is not None:
            self._conn.rollback()
            self._conn.close()
            self._conn = None
