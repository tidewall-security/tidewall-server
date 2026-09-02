"""The rule-set backfill migration, run for real.

Existing databases carry only `input` and `output` rule sets, because both
creation paths held their own copy of that pair. New installs are fixed by the
code change; deployed databases need this migration, and until they have it the
guard keeps resolving three event types to the input engine.

The migration is run through alembic against a real file database rather than
asserted against `Base.metadata.create_all()`, which would describe the ORM's
idea of the schema and say nothing about what an upgrade actually produces.
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

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


def _legacy_policy(engine, *, report_only_on_input: bool | None, with_access_rule: bool) -> str:
    """A policy as an existing deployment holds it: input and output only."""
    pid = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO policies "
                "(id, name, type, report_only, is_default, created_at, updated_at) "
                "VALUES (:id, :n, 'application', 0, 0, :t, :t)"
            ),
            {"id": pid, "n": f"legacy-{pid[:8]}", "t": datetime.now(UTC).isoformat(sep=" ")},
        )
        for et in ("input", "output"):
            rs_id = str(uuid.uuid4())
            conn.execute(
                text(
                    "INSERT INTO rule_sets (id, policy_id, event_type, detectors, report_only) "
                    "VALUES (:id, :p, :e, :d, :r)"
                ),
                {
                    "id": rs_id,
                    "p": pid,
                    "e": et,
                    "d": '{"malicious_prompt": {"enabled": true, "action": "block"}}',
                    "r": report_only_on_input if et == "input" else None,
                },
            )
            if et == "input" and with_access_rule:
                conn.execute(
                    text(
                        "INSERT INTO access_rules "
                        "(id, rule_set_id, name, conditions, then_action, else_action, sort_order) "
                        "VALUES (:id, :rs, 'blocker', '{}', 'block', 'continue', 0)"
                    ),
                    {"id": str(uuid.uuid4()), "rs": rs_id},
                )
    return pid


@pytest.fixture
def migrated_db(tmp_path):
    db = tmp_path / "backfill.db"
    _alembic(db, "upgrade", "head")
    return db


def test_backfill_gives_every_policy_a_rule_set_per_event_type(migrated_db):
    from app.models import EVENT_TYPES

    engine = create_engine(f"sqlite:///{migrated_db}")
    # A policy carrying exactly the fields a whole-row copy would wrongly
    # inherit: an access rule and a non-null report_only override on `input`.
    pid = _legacy_policy(engine, report_only_on_input=True, with_access_rule=True)

    _alembic(migrated_db, "upgrade", "head")  # no-op; rows inserted after head

    # Re-run the backfill explicitly by downgrading one and upgrading again.
    _alembic(migrated_db, "downgrade", "-1")
    _alembic(migrated_db, "upgrade", "head")

    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT event_type, detectors, report_only FROM rule_sets WHERE policy_id = :p"),
            {"p": pid},
        ).fetchall()

    assert {r[0] for r in rows} == set(EVENT_TYPES)

    inp = next(r for r in rows if r[0] == "input")
    for et in ("tool_input", "tool_output", "tool_listing"):
        new = next(r for r in rows if r[0] == et)
        assert new[1] == inp[1], f"{et} must inherit input's detectors"
        assert new[2] is None, f"{et} must NOT inherit input's report_only override"

    with engine.begin() as conn:
        leaked = conn.execute(
            text(
                "SELECT count(*) FROM access_rules ar JOIN rule_sets rs ON ar.rule_set_id = rs.id "
                "WHERE rs.policy_id = :p AND rs.event_type IN "
                "('tool_input','tool_output','tool_listing')"
            ),
            {"p": pid},
        ).scalar()
    assert leaked == 0, "backfilled rows must not inherit input's access rules"


def test_backfill_is_idempotent(migrated_db):
    engine = create_engine(f"sqlite:///{migrated_db}")
    pid = _legacy_policy(engine, report_only_on_input=None, with_access_rule=False)

    for _ in range(2):
        _alembic(migrated_db, "downgrade", "-1")
        _alembic(migrated_db, "upgrade", "head")

    with engine.begin() as conn:
        n = conn.execute(text("SELECT count(*) FROM rule_sets WHERE policy_id = :p"), {"p": pid}).scalar()
    from app.models import EVENT_TYPES

    assert n == len(EVENT_TYPES), "re-running the migration must not duplicate rows"
