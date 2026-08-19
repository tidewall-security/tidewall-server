"""The step-6 migration, exercised through the real Alembic CLI.

Source inspection made the abort path look safe. It was not: Alembic reports
non-transactional DDL on SQLite, so raising part-way leaves whatever DDL already
ran. These tests run the migration for real rather than reasoning about it.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from sqlalchemy import create_engine, inspect, text

STEP5_HEAD = "64c197391e55"
STEP6_HEAD = "56bc13c16fef"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _alembic(db_path, *args):
    env = dict(os.environ, DB_URL=f"sqlite:///{db_path}")
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


def _revision(db_path) -> str | None:
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        with engine.connect() as conn:
            return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    finally:
        engine.dispose()


@pytest.fixture
def at_step5(tmp_path):
    db = tmp_path / "m.db"
    result = _alembic(db, "upgrade", STEP5_HEAD)
    assert result.returncode == 0, result.stderr
    return db


def test_the_upgrade_backfills_the_content_policy_from_its_parent(at_step5):
    engine = create_engine(f"sqlite:///{at_step5}")
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO interactions (request_id, timestamp, event_type, policy_id, policy_name, "
                "blocked, transformed, latency_ms, evidence_schema_version, content_available) "
                "VALUES ('tw_0000000000000001','2026-08-19T00:00:00Z','input','pol-a','p',0,0,1.0,1,1)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO interaction_contents (interaction_id, byte_size, captured_at) "
                "VALUES (1, 10, '2026-08-19 00:00:00.000000')"
            )
        )
    engine.dispose()

    assert _alembic(at_step5, "upgrade", STEP6_HEAD).returncode == 0

    engine = create_engine(f"sqlite:///{at_step5}")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT policy_id FROM interaction_contents")).scalar() == "pol-a"
    names = {c["name"] for c in inspect(engine).get_columns("interaction_contents")}
    assert "policy_id" in names
    indexes = {i["name"] for i in inspect(engine).get_indexes("interaction_contents")}
    assert "ix_interaction_contents_policy_id" in indexes
    engine.dispose()


def test_an_orphan_content_row_aborts_and_changes_nothing(at_step5):
    """The failing case, run for real.

    An earlier version added the column first and then raised, leaving a
    database that was neither the old schema nor the new one -- and whose retry
    failed at ADD COLUMN instead of re-reporting the real problem.
    """
    engine = create_engine(f"sqlite:///{at_step5}")
    with engine.begin() as conn:
        conn.execute(text("PRAGMA foreign_keys=OFF"))
        conn.execute(
            text(
                "INSERT INTO interaction_contents (interaction_id, byte_size, captured_at) "
                "VALUES (999, 10, '2026-08-19 00:00:00.000000')"
            )
        )
    before = {c["name"] for c in inspect(engine).get_columns("interaction_contents")}
    engine.dispose()

    result = _alembic(at_step5, "upgrade", STEP6_HEAD)
    assert result.returncode != 0
    assert "no resolvable policy" in (result.stderr + result.stdout)

    assert _revision(at_step5) == STEP5_HEAD, "the revision moved despite the abort"

    engine = create_engine(f"sqlite:///{at_step5}")
    after = {c["name"] for c in inspect(engine).get_columns("interaction_contents")}
    engine.dispose()
    assert after == before, f"the abort left DDL behind: {after - before}"

    # And the retry re-reports the real problem rather than failing at
    # ADD COLUMN, which is the observable consequence of a half-applied abort.
    retry = _alembic(at_step5, "upgrade", STEP6_HEAD)
    assert "no resolvable policy" in (retry.stderr + retry.stdout)


def test_capture_still_works_after_the_upgrade(at_step5):
    """A NOT NULL column with no writer would fail the first capture after
    upgrade. The backfill only repairs old rows."""
    assert _alembic(at_step5, "upgrade", STEP6_HEAD).returncode == 0

    from sqlalchemy.orm import sessionmaker

    from app.db.models import Interaction, InteractionContent, Policy
    from app.interaction_log import InteractionLog

    engine = create_engine(f"sqlite:///{at_step5}")
    Session = sessionmaker(bind=engine)
    session = Session()
    session.add(Policy(id="pol-a", name="p", type="application", raw_content_enabled=True))
    session.commit()
    session.close()

    InteractionLog(Session).log_event(
        request_id="tw_00000000000000ff",
        timestamp="2026-08-19T00:00:00Z",
        event_type="input",
        policy="p",
        policy_id="pol-a",
        blocked=False,
        transformed=False,
        latency_ms=1.0,
        evidence={},
        content={"input": [{"content": "x"}], "output": None, "matches": None},
        capture_enabled=True,
    )

    session = Session()
    try:
        stored = session.query(InteractionContent).one()
        event = session.query(Interaction).one()
        assert stored.policy_id == event.policy_id == "pol-a"
    finally:
        session.close()
        engine.dispose()


def test_the_downgrade_removes_everything_it_added(at_step5):
    assert _alembic(at_step5, "upgrade", STEP6_HEAD).returncode == 0
    result = _alembic(at_step5, "downgrade", STEP5_HEAD)
    assert result.returncode == 0, result.stderr

    engine = create_engine(f"sqlite:///{at_step5}")
    content = {c["name"] for c in inspect(engine).get_columns("interaction_contents")}
    audit = {c["name"] for c in inspect(engine).get_columns("content_access_audit")}
    engine.dispose()

    assert "policy_id" not in content
    assert not {"actor_role", "grant_used", "outcome", "reason", "attempt_id", "source_ip"} & audit
    assert "tier" in audit, "the downgrade removed a step-5 column"
