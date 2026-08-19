"""The content-export schema, exercised through the real Alembic CLI.

Source inspection makes a migration look right. Step 6's abort path looked right
and left a column behind, so these run it.
"""

from __future__ import annotations

import os
import pathlib
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


def _normalise(rows):
    """Reflected constraint dicts, as a comparable set."""
    out = set()
    for row in rows:
        out.add(
            tuple(
                sorted(
                    (k, repr(v) if isinstance(v, list | dict) else v)
                    for k, v in row.items()
                    if k not in ("dialect_options", "comment", "duplicates_index")
                )
            )
        )
    return out


def _check_names(engine, table):
    """SQLite does not reflect CHECK constraints, so read them from the DDL."""
    with engine.connect() as conn:
        ddl = conn.execute(text("SELECT sql FROM sqlite_master WHERE type='table' AND name=:t"), {"t": table}).scalar()
    return {part.split()[0] for part in (ddl or "").split("CONSTRAINT ")[1:]}


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
        assert a == b, f"{table} columns differ: only migrated={a - b} only fresh={b - a}"

        # Columns alone would pass with every CHECK, UNIQUE, index and foreign
        # key missing from one side, which is most of what these tables are.
        for reflect in ("get_indexes", "get_unique_constraints", "get_foreign_keys"):
            am = _normalise(getattr(inspect(migrated), reflect)(table))
            bm = _normalise(getattr(inspect(fresh), reflect)(table))
            assert am == bm, f"{table} {reflect} differ: only migrated={am - bm} only fresh={bm - am}"

        checks_m = _check_names(migrated, table)
        checks_f = _check_names(fresh, table)
        assert checks_m == checks_f, f"{table} checks differ: {checks_m ^ checks_f}"

    target_migrated = {c["name"] for c in inspect(migrated).get_columns("export_targets")}
    target_fresh = {c["name"] for c in inspect(fresh).get_columns("export_targets")}
    assert {"allow_content_export", "content_export_policy_id", "content_export_views"} <= target_migrated
    assert target_migrated == target_fresh

    migrated.dispose()
    fresh.dispose()


def test_a_partial_failure_is_retryable(at_step7, tmp_path):
    """Alembic reports "Will assume non-transactional DDL" on SQLite, so a
    failure part-way through leaves whatever already ran and the revision
    unchanged. A retry must then re-run the whole upgrade and skip what exists,
    rather than failing on a duplicate column and needing manual repair.

    Simulated by running the upgrade with the last index creation sabotaged,
    then running it again unmodified.
    """
    import shutil

    revision = os.path.join(ROOT, "alembic", "versions", "1b42ababed28_content_export.py")
    backup = tmp_path / "revision.bak"
    shutil.copy(revision, backup)

    original = pathlib.Path(revision).read_text()
    sabotaged = original.replace(
        '    _index("ix_content_export_notes_attempt_id", "content_export_notes", ["attempt_id"])',
        '    raise RuntimeError("simulated failure after most of the DDL")',
    )
    assert sabotaged != original, "the sabotage anchor no longer exists"

    try:
        pathlib.Path(revision).write_text(sabotaged)
        failed = _alembic(at_step7, "upgrade", "head")
        assert failed.returncode != 0, "the sabotage did not fail the upgrade"
    finally:
        shutil.copy(backup, revision)

    # The revision did not advance, and some DDL is already there.
    engine = create_engine(f"sqlite:///{at_step7}")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == STEP7_HEAD
    partial = set(inspect(engine).get_table_names())
    engine.dispose()
    assert "content_export_attempts" in partial, "nothing was applied, so the retry proves nothing"

    # The retry must succeed rather than fail on a duplicate.
    retry = _alembic(at_step7, "upgrade", "head")
    assert retry.returncode == 0, retry.stderr

    engine = create_engine(f"sqlite:///{at_step7}")
    names = set(inspect(engine).get_table_names())
    indexes = {i["name"] for i in inspect(engine).get_indexes("content_export_notes")}
    engine.dispose()
    assert {"content_export_attempts", "content_export_reconciliations", "content_export_notes"} <= names
    assert "ix_content_export_notes_attempt_id" in indexes


def test_the_idempotency_reservation_is_unique_per_credential(at_step7):
    """The constraint the whole reservation protocol rests on. A check-then-
    insert lets two concurrent requests with one key both pass the check and
    disclose twice; this is what stops it."""
    assert _alembic(at_step7, "upgrade", "head").returncode == 0
    engine = create_engine(f"sqlite:///{at_step7}")
    with engine.begin() as conn:
        _insert_attempt(conn, attempt_id="a", api_key_id="k1", idempotency_key_digest="d1")
        # A different credential may use the same key value.
        _insert_attempt(conn, attempt_id="b", api_key_id="k2", idempotency_key_digest="d1")
    with pytest.raises(Exception):
        with engine.begin() as conn:
            _insert_attempt(conn, attempt_id="c", api_key_id="k1", idempotency_key_digest="d1")
    engine.dispose()


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO content_export_reconciliations "
        "(attempt_id, from_state, to_state, evidence, reconciled_at) "
        "VALUES ('a', 'indeterminate', 'pending', 'e', '2026-08-19 00:00:00.000000')",
        "INSERT INTO content_export_notes (attempt_id, kind, detail, created_at) "
        "VALUES ('a', 'something_else', 'd', '2026-08-19 00:00:00.000000')",
    ],
)
def test_the_evidence_vocabularies_are_closed(at_step7, statement):
    assert _alembic(at_step7, "upgrade", "head").returncode == 0
    engine = create_engine(f"sqlite:///{at_step7}")
    with engine.begin() as conn:
        _insert_attempt(conn)
    with pytest.raises(Exception):
        with engine.begin() as conn:
            conn.execute(text(statement))
    engine.dispose()


def test_a_valid_reconciliation_and_note_insert(at_step7):
    """Otherwise the two vocabulary tests above would pass on a malformed
    statement rather than on the constraint they name."""
    assert _alembic(at_step7, "upgrade", "head").returncode == 0
    engine = create_engine(f"sqlite:///{at_step7}")
    with engine.begin() as conn:
        _insert_attempt(conn)
        conn.execute(
            text(
                "INSERT INTO content_export_reconciliations "
                "(attempt_id, from_state, to_state, evidence, reconciled_at) "
                "VALUES ('a', 'indeterminate', 'succeeded', 'receiver log', '2026-08-19 00:00:00.000000')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO content_export_notes (attempt_id, kind, detail, created_at) "
                "VALUES ('a', 'settlement_lost', 'observed=succeeded stored=failed', "
                "'2026-08-19 00:00:00.000000')"
            )
        )
    engine.dispose()
