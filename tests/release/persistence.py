"""Drive PRODUCTION CAPTURE and measure what it actually put on disk.

The capture-on suite asserted exact cardinality against a synthetic
`policies(id, name)` database it populated itself. Disabling production
capture would not have failed a single named case: the cases called
`ScannerEngine.scan(..., vault=None)` and inspected `ScanResult` fields, and
nothing was ever written.

So capture runs for real -- `build_content` and `capture_content`, the
functions the guard path uses -- against a real SQLite file, and the
measurements are taken off the bytes:

  * the WHOLE-STORE DELTA, so an occurrence in a column nobody declared is
    visible;
  * the CANONICAL LIVE IMAGE, rebuilt, so the count is state and not page
    churn;
  * the COPY MAP prediction, so the expected count is derived rather than
    observed and agreed with.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from app.db.models import Base, Interaction, Policy
from app.services.content_capture import build_content, capture_content


class CaptureNotPerformed(Exception):
    """Nothing was written, so a count over the store measures nothing."""


def capture_into(db: Path, *, canary: str, retention_days: int | None = 30) -> int:
    """Run the real capture path once. Returns the content row id.

    Uses `build_content` + `capture_content` -- the same pair the guard path
    calls -- rather than inserting a row directly, so a change to what capture
    stores changes what this measures.
    """
    engine = sa.create_engine(f"sqlite:///{db}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        policy = Policy(
            name="release-gate",
            type="application",
            description="d",
            report_only=False,
            is_default=True,
        )
        session.add(policy)
        session.flush()

        interaction = Interaction(
            request_id="tw_release_gate",
            timestamp=datetime.now(UTC),
            event_type="input",
            policy_id=policy.id,
            policy_name=policy.name,
            blocked=False,
            transformed=False,
            latency_ms=0,
            evidence_schema_version=1,
            content_available=True,
        )
        session.add(interaction)
        session.flush()

        prepared = build_content(
            input_messages=[{"role": "user", "content": canary}],
            output_messages=None,
            matches={"detector": [{"value": canary}]},
            tools=None,
            retention_days=retention_days,
        )
        capture_content(session, interaction=interaction, prepared=prepared)
        session.commit()

        rows = session.execute(sa.text("SELECT count(*) FROM interaction_contents")).scalar_one()
        if not rows:
            raise CaptureNotPerformed(
                "capture_content added no row, so any later count is measuring "
                "an empty store rather than what capture wrote"
            )
        return rows
    finally:
        session.close()
        engine.dispose()


def occurrences_in_canonical_image(db: Path, into: Path, needle: bytes) -> int:
    """Count in the REBUILT image: state, not page churn."""
    from tests.release.counts import canonical_live_image

    return canonical_live_image(db, into).read_bytes().count(needle)


def occurrences_in_working_file(db: Path, needle: bytes) -> int:
    """Count in the working database, sidecars included."""
    total = 0
    for suffix in ("", "-wal", "-journal"):
        path = Path(str(db) + suffix)
        if path.exists():
            total += path.read_bytes().count(needle)
    return total


def live_cells_holding(db: Path, value: str) -> set[tuple[str, int, str]]:
    """Every live cell holding `value`, across the whole store."""
    from tests.release.attribution import cells_holding

    conn = sqlite3.connect(db)
    try:
        return cells_holding(conn, value)
    finally:
        conn.close()


#: The only BLOB column in the production schema. Raw bytes live here or
#: nowhere, which is why the raw-bytes representation is a STORAGE property
#: rather than an ingress one.
BLOB_COLUMN = ("vaults", "data")


def store_raw_bytes(db: Path, *, payload: bytes) -> None:
    """Write `payload` into production's only binary column.

    `ScannerEngine.scan` takes `str`, so a BLOB cannot be planted at the text
    ingress at all -- and a driver that encodes bytes and immediately decodes
    them back to text has not exercised raw-byte storage. It has exercised
    text.
    """
    from datetime import timedelta

    from app.db.models import Vault

    engine = sa.create_engine(f"sqlite:///{db}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        now = datetime.now(UTC)
        session.add(Vault(id="release-gate-vault", data=payload, created_at=now, expires_at=now + timedelta(days=1)))
        session.commit()
    finally:
        session.close()
        engine.dispose()


def stored_type(db: Path, table: str, column: str) -> str:
    """SQLite's own storage class for the value, not Python's opinion."""
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(f'SELECT typeof("{column}") FROM "{table}"').fetchone()
        return row[0] if row else ""
    finally:
        conn.close()
