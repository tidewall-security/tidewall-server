"""The device identity migration, run for real.

Every other device test builds its schema with `Base.metadata.create_all()`,
which produces the ORM's idea of the tables and says nothing about what an
upgraded database actually contains. That gap hid a live defect: the migration
made `devices.fingerprint` nullable but never dropped the unnamed
`UNIQUE (fingerprint)` constraint the original table was created with, because
Alembic's batch mode silently carries forward a constraint it cannot name. A
migrated deployment therefore still refused a second device reporting the same
fingerprint — the denial-of-enrolment half of P0-11 — while the tests were
green.

These tests run alembic against a real file database and inspect the result.
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

REPO_ROOT = Path(__file__).resolve().parent.parent


def _alembic(db_path: Path, *args: str) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_ROOT,
        env={"DB_URL": f"sqlite:///{db_path}", "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"alembic {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")


@pytest.fixture
def migrated_db(tmp_path):
    db_path = tmp_path / "migrated.db"
    _alembic(db_path, "upgrade", "head")
    engine = create_engine(f"sqlite:///{db_path}")
    yield engine
    engine.dispose()


def test_fingerprint_is_no_longer_unique_in_a_migrated_database(migrated_db):
    """Two devices may report the same fingerprint. That is the point of P0-11.

    Asserted by inserting, not by reading DDL: the constraint that broke this
    was invisible to the ORM and to `create_all`.
    """
    with migrated_db.begin() as conn:
        for name in ("alice", "bob"):
            conn.execute(
                text(
                    "INSERT INTO devices (id, installation_id, fingerprint, device_name, "
                    "user_name, user_email, browser, os, ext_version, status, last_seen, created_at) "
                    "VALUES (:id, :inst, 'fp-shared', :name, :name, :email, 'chrome', 'macos', "
                    "'1.0.0', 'active', datetime('now'), datetime('now'))"
                ),
                {"id": str(uuid.uuid4()), "inst": f"inst-{name}", "name": name, "email": f"{name}@example.com"},
            )

        count = conn.execute(text("SELECT COUNT(*) FROM devices WHERE fingerprint = 'fp-shared'")).scalar()
    assert count == 2


def test_installation_id_is_unique_in_a_migrated_database(migrated_db):
    """The replacement identity constraint really is enforced."""
    from sqlalchemy.exc import IntegrityError

    insert = text(
        "INSERT INTO devices (id, installation_id, device_name, user_name, user_email, "
        "browser, os, ext_version, status, last_seen, created_at) "
        "VALUES (:id, 'inst-duplicate', 'd', 'u', 'u@example.com', 'chrome', 'macos', "
        "'1.0.0', 'active', datetime('now'), datetime('now'))"
    )
    with migrated_db.begin() as conn:
        conn.execute(insert, {"id": str(uuid.uuid4())})

    with pytest.raises(IntegrityError), migrated_db.begin() as conn:
        conn.execute(insert, {"id": str(uuid.uuid4())})


def test_registration_token_policy_has_a_foreign_key_in_a_migrated_database(migrated_db):
    """A migrated database must not lack integrity a fresh one has.

    The column was added with a plain `op.add_column`, so the ORM's
    `ForeignKey("policies.id", ondelete="SET NULL")` existed only in databases
    created from metadata.
    """
    fks = inspect(migrated_db).get_foreign_keys("registration_tokens")
    policy_fk = [fk for fk in fks if fk["constrained_columns"] == ["policy_id"]]

    assert policy_fk, f"registration_tokens.policy_id has no foreign key; found {fks}"
    assert policy_fk[0]["referred_table"] == "policies"


def test_the_migration_round_trips(tmp_path):
    db_path = tmp_path / "roundtrip.db"
    _alembic(db_path, "upgrade", "head")
    _alembic(db_path, "downgrade", "-1")
    _alembic(db_path, "upgrade", "head")

    engine = create_engine(f"sqlite:///{db_path}")
    try:
        columns = {c["name"] for c in inspect(engine).get_columns("devices")}
    finally:
        engine.dispose()
    assert "installation_id" in columns


def test_legacy_registration_tokens_do_not_survive_the_migration(tmp_path):
    """A surviving pre-migration token would enrol unscoped devices.

    `policy_id` is nullable so the column can be added to a populated table.
    That means a token created before this migration keeps NULL, the middleware
    still accepts it, and enrolment copies the NULL onto the new device — which
    guard reads as "use the default policy". The scope binding this migration
    exists to establish would be silently absent for exactly the tokens most
    likely to still be in use.
    """
    db_path = tmp_path / "legacy.db"
    _alembic(db_path, "upgrade", "c8f31b0d7a45")

    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO registration_tokens (id, name, token_hash, token_prefix, created_at) "
                    "VALUES (:id, 'legacy', 'hash', 'rt_ab...', datetime('now'))"
                ),
                {"id": str(uuid.uuid4())},
            )
    finally:
        engine.dispose()

    _alembic(db_path, "upgrade", "head")

    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with engine.begin() as conn:
            remaining = conn.execute(text("SELECT COUNT(*) FROM registration_tokens")).scalar()
    finally:
        engine.dispose()
    assert remaining == 0, "a legacy token survived and can still enrol unscoped devices"


def test_the_policy_bindings_restrict_deletion_in_a_migrated_database(migrated_db):
    """Guard reads a null policy as 'use the default', so SET NULL on delete
    would silently rebind. Both scope foreign keys must be RESTRICT."""
    fks = {
        table: {fk["name"]: fk for fk in inspect(migrated_db).get_foreign_keys(table)}
        for table in ("devices", "registration_tokens")
    }

    assert fks["devices"]["fk_devices_policy_id"]["options"]["ondelete"] == "RESTRICT"
    assert fks["registration_tokens"]["fk_registration_tokens_policy_id"]["options"]["ondelete"] == "RESTRICT"
