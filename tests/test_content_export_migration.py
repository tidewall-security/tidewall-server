"""The content-export schema, exercised through the real Alembic CLI.

Source inspection makes a migration look right. Step 6's abort path looked right
and left a column behind, so these run it.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, inspect, text

STEP7_HEAD = "56bc13c16fef"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _alembic(db_path, *args):
    env = dict(os.environ, DB_URL=f"sqlite:///{db_path}")
    return subprocess.run([sys.executable, "-m", "alembic", *args], cwd=ROOT, env=env, capture_output=True, text=True)


@pytest.fixture
def at_step7(tmp_path):
    db = tmp_path / "m.db"
    result = _alembic(db, "upgrade", STEP7_HEAD)
    assert result.returncode == 0, result.stderr
    return db


def test_existing_targets_are_opted_out(at_step7):
    """Seeded BEFORE the upgrade. A default that only applies to new rows would
    leave every existing target silently exportable, which is this step
    inverted."""
    engine = create_engine(f"sqlite:///{at_step7}")
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO export_targets (id, name, type, config, format, events, enabled, created_at) "
                "VALUES ('t1', 'legacy', 'webhook', '{}', 'ocsf', '[]', 1, '2026-08-19 00:00:00.000000')"
            )
        )
    engine.dispose()

    assert _alembic(at_step7, "upgrade", "head").returncode == 0

    engine = create_engine(f"sqlite:///{at_step7}")
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT allow_content_export, content_export_policy_id, content_export_views " "FROM export_targets")
        ).one()
    engine.dispose()
    assert row[0] == 0, "an existing target came out opted IN"
    assert row[1] is None
    assert row[2] in ("[]", None)


def test_the_three_tables_are_created(at_step7):
    assert _alembic(at_step7, "upgrade", "head").returncode == 0
    engine = create_engine(f"sqlite:///{at_step7}")
    names = set(inspect(engine).get_table_names())
    engine.dispose()
    assert {"content_export_attempts", "content_export_reconciliations", "content_export_notes"} <= names


def _insert_attempt(conn, **over):
    values = dict(
        attempt_id="a",
        interaction_id=1,
        policy_id="p",
        target_id="t",
        view="full",
        state="pending",
        payload_bytes=1,
        created_at="2026-08-19 00:00:00.000000",
        boot_id="b",
        destination_host="h",
        destination_port=443,
        destination_addrs='["1.2.3.4"]',
        target_config_digest="d",
        fingerprint="f",
        settled_at=None,
        transport_status=None,
    )
    values.update(over)
    columns = ", ".join(values)
    binds = ", ".join(f":{k}" for k in values)
    conn.execute(text(f"INSERT INTO content_export_attempts ({columns}) VALUES ({binds})"), values)


@pytest.mark.parametrize(
    "over",
    [
        # A terminal state must carry settled_at.
        {"state": "succeeded"},
        # A pending row must not.
        {"settled_at": "2026-08-19 00:00:00.000000"},
        # ... nor a transport status.
        {"transport_status": 204},
        # An unknown state.
        {"state": "sent"},
        # A status outside the HTTP range.
        {"state": "failed", "settled_at": "2026-08-19 00:00:00.000000", "transport_status": 42},
    ],
)
def test_the_attempt_constraints_reject_an_impossible_row(at_step7, over):
    assert _alembic(at_step7, "upgrade", "head").returncode == 0
    engine = create_engine(f"sqlite:///{at_step7}")
    with pytest.raises(Exception):
        with engine.begin() as conn:
            _insert_attempt(conn, **over)
    engine.dispose()


def test_a_reconciliation_and_a_note_require_a_real_attempt(at_step7):
    assert _alembic(at_step7, "upgrade", "head").returncode == 0
    engine = create_engine(f"sqlite:///{at_step7}")
    for statement in (
        "INSERT INTO content_export_reconciliations "
        "(attempt_id, from_state, to_state, evidence, reconciled_at) "
        "VALUES ('nope', 'indeterminate', 'failed', 'e', '2026-08-19 00:00:00.000000')",
        "INSERT INTO content_export_notes (attempt_id, kind, detail, created_at) "
        "VALUES ('nope', 'settlement_lost', 'd', '2026-08-19 00:00:00.000000')",
    ):
        with pytest.raises(Exception):
            with engine.begin() as conn:
                conn.execute(text("PRAGMA foreign_keys=ON"))
                conn.execute(text(statement))
    engine.dispose()


def test_downgrade_removes_everything_it_added(at_step7):
    assert _alembic(at_step7, "upgrade", "head").returncode == 0
    assert _alembic(at_step7, "downgrade", STEP7_HEAD).returncode == 0
    engine = create_engine(f"sqlite:///{at_step7}")
    names = set(inspect(engine).get_table_names())
    columns = {c["name"] for c in inspect(engine).get_columns("export_targets")}
    engine.dispose()
    assert not {"content_export_attempts", "content_export_reconciliations", "content_export_notes"} & names
    assert not {"allow_content_export", "content_export_policy_id", "content_export_views"} & columns
    assert "enabled" in columns, "the downgrade removed a pre-existing column"


def test_a_valid_row_inserts(at_step7):
    """Otherwise every constraint test above would pass on a malformed helper
    rather than on the constraint it names."""
    assert _alembic(at_step7, "upgrade", "head").returncode == 0
    engine = create_engine(f"sqlite:///{at_step7}")
    with engine.begin() as conn:
        _insert_attempt(conn)
        _insert_attempt(
            conn,
            attempt_id="b",
            state="succeeded",
            settled_at="2026-08-19 00:00:01.000000",
            transport_status=204,
        )
    with engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM content_export_attempts")).scalar() == 2
    engine.dispose()


def test_the_migrated_schema_matches_the_orm(at_step7, tmp_path):
    """A fresh create_all and the migration must agree on the new tables, or a
    developer database and a deployed one differ."""
    from app.db.models import Base

    assert _alembic(at_step7, "upgrade", "head").returncode == 0
    migrated = create_engine(f"sqlite:///{at_step7}")

    fresh_path = tmp_path / "fresh.db"
    fresh = create_engine(f"sqlite:///{fresh_path}")
    Base.metadata.create_all(fresh)

    for table in ("content_export_attempts", "content_export_reconciliations", "content_export_notes"):
        a = {(c["name"], str(c["type"]), c["nullable"]) for c in inspect(migrated).get_columns(table)}
        b = {(c["name"], str(c["type"]), c["nullable"]) for c in inspect(fresh).get_columns(table)}
        assert a == b, f"{table} differs: only migrated={a - b} only fresh={b - a}"

    target_migrated = {c["name"] for c in inspect(migrated).get_columns("export_targets")}
    target_fresh = {c["name"] for c in inspect(fresh).get_columns("export_targets")}
    assert {"allow_content_export", "content_export_policy_id", "content_export_views"} <= target_migrated
    assert target_migrated == target_fresh

    migrated.dispose()
    fresh.dispose()
