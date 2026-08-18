"""P0-6 step 4: the audit record stores no prompt, and reads are scoped.

Four columns on `interactions` carried content: `input_messages`,
`output_messages`, `detectors_json` and `summary`. The last is the one worth
naming — it reads like metadata, and it carried the matched access-rule name
and detector-derived strings, and was displayed *and searched* in the UI. I
listed three and called the inventory complete; the design review found the
fourth.
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

REPO_ROOT = Path(__file__).resolve().parent.parent
CANARY = "CANARY-store-8b2e-secret"
GONE = ("input_messages", "output_messages", "detectors_json", "summary")


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


# ---------------------------------------------------------------------------
# The migration
# ---------------------------------------------------------------------------


def test_the_migration_removes_the_content_columns_and_the_rows(tmp_path):
    """Both halves matter. Dropping the columns without deleting the rows would
    leave the prompts in the file; deleting the rows without dropping the
    columns would leave the sink open for the next write."""
    db = tmp_path / "legacy.db"
    _alembic(db, "upgrade", "d5a71f3c8e02")

    engine = create_engine(f"sqlite:///{db}")
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO interactions (request_id, timestamp, event_type, policy_name, "
                    "blocked, transformed, latency_ms, summary, input_messages, detectors_json) "
                    "VALUES (:rid, '2026-01-01T00:00:00Z', 'input', 'p', 0, 0, 1.0, "
                    ":summary, :messages, :detectors)"
                ),
                {
                    "rid": str(uuid.uuid4()),
                    "summary": f"Blocked by access rule: {CANARY}",
                    "messages": json.dumps([{"role": "user", "content": f"my secret is {CANARY}"}]),
                    "detectors": json.dumps({"pii": {"data": {"entities": [{"value": CANARY}]}}}),
                },
            )
    finally:
        engine.dispose()

    _alembic(db, "upgrade", "head")

    engine = create_engine(f"sqlite:///{db}")
    try:
        columns = {c["name"] for c in inspect(engine).get_columns("interactions")}
        with engine.begin() as conn:
            remaining = conn.execute(text("SELECT COUNT(*) FROM interactions")).scalar()
    finally:
        engine.dispose()

    assert remaining == 0, "legacy rows survived, and every one of them holds a prompt"
    for column in GONE:
        assert column not in columns, f"{column} is still a column"


def test_the_canary_is_not_recoverable_from_the_file(tmp_path):
    """Logical deletion is not erasure.

    SQLite leaves deleted pages in the file and the WAL, so a row that is gone
    from a query can still be read out of the bytes. Distinguish the two: this
    asserts the stronger property after a checkpoint and VACUUM, because
    otherwise the migration only *looks* like it removed the content.
    """
    db = tmp_path / "erase.db"
    _alembic(db, "upgrade", "d5a71f3c8e02")

    engine = create_engine(f"sqlite:///{db}")
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO interactions (request_id, timestamp, event_type, policy_name, "
                    "blocked, transformed, latency_ms, input_messages) "
                    "VALUES (:rid, '2026-01-01T00:00:00Z', 'input', 'p', 0, 0, 1.0, :messages)"
                ),
                {"rid": str(uuid.uuid4()), "messages": json.dumps([{"content": CANARY}])},
            )
    finally:
        engine.dispose()

    _alembic(db, "upgrade", "head")

    engine = create_engine(f"sqlite:///{db}")
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.exec_driver_sql("VACUUM")
            conn.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        engine.dispose()

    for path in (db, Path(f"{db}-wal"), Path(f"{db}-shm")):
        if path.exists():
            assert CANARY.encode() not in path.read_bytes(), f"the canary survives in {path.name}"


def test_the_future_tables_exist_and_are_empty(tmp_path):
    """Created inert by the same destructive revision. One rebuild of this
    table is better than two."""
    db = tmp_path / "future.db"
    _alembic(db, "upgrade", "head")

    engine = create_engine(f"sqlite:///{db}")
    try:
        names = set(inspect(engine).get_table_names())
        with engine.begin() as conn:
            counts = {
                t: conn.execute(text(f"SELECT COUNT(*) FROM {t}")).scalar()
                for t in ("interaction_contents", "content_access_audit")
            }
    finally:
        engine.dispose()

    assert {"interaction_contents", "content_access_audit"} <= names
    assert counts == {"interaction_contents": 0, "content_access_audit": 0}


def test_content_deletion_cascades_from_the_event(tmp_path):
    """Deleting an event must not orphan its content."""
    db = tmp_path / "cascade.db"
    _alembic(db, "upgrade", "head")

    engine = create_engine(f"sqlite:///{db}")
    try:
        fks = inspect(engine).get_foreign_keys("interaction_contents")
        assert any(fk["referred_table"] == "interactions" and fk["options"].get("ondelete") == "CASCADE" for fk in fks)
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# Reads are scoped
# ---------------------------------------------------------------------------


@pytest.fixture
def scoped_app():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.auth.key_utils import generate_key, hash_key, key_prefix
    from app.auth.middleware import AuthMiddleware
    from app.db.models import APIKey, Base, Interaction
    from app.interaction_log import InteractionLog
    from app.routes import logs

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    keys = {}
    session = SessionLocal()
    for name, role, policy in (
        ("admin", "admin", None),
        ("viewer_a", "viewer", "policy-a"),
        ("viewer_b", "viewer", "policy-b"),
        ("viewer_unbound", "viewer", None),
    ):
        raw = generate_key(prefix="ak")
        keys[name] = raw
        session.add(APIKey(name=name, key_hash=hash_key(raw), key_prefix=key_prefix(raw), role=role, policy_id=policy))
    for idx, policy in enumerate(("policy-a", "policy-b")):
        session.add(
            Interaction(
                request_id=f"tw_{idx}",
                timestamp=f"2026-08-19T0{idx}:00:00Z",
                event_type="input",
                policy_id=policy,
                policy_name=policy,
                blocked=False,
                transformed=False,
                status="allowed",
                latency_ms=1.0,
                evidence_json={"pii": {"detected": True}},
            )
        )
    session.commit()
    session.close()

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = SessionLocal
    app.state.interaction_log = InteractionLog(SessionLocal)
    app.include_router(logs.router)
    return TestClient(app), keys


def _get(client, key, path="/v1/logs"):
    return client.get(path, headers={"Authorization": f"Bearer {key}"})


def test_a_viewer_sees_only_its_own_policy(scoped_app):
    client, keys = scoped_app

    rows = _get(client, keys["viewer_a"]).json()

    assert [r["policy_id"] for r in rows] == ["policy-a"]


def test_a_viewer_cannot_see_another_policy(scoped_app):
    client, keys = scoped_app

    rows = _get(client, keys["viewer_b"]).json()

    assert all(r["policy_id"] == "policy-b" for r in rows)
    assert not any(r["policy_id"] == "policy-a" for r in rows)


def test_an_unbound_viewer_sees_nothing_rather_than_everything(scoped_app):
    """The important case.

    Treating a null binding as a wildcard is exactly how one credential becomes
    an organisation-wide disclosure credential, which is half of why this is a
    P0. Refusing is the safe direction; the fix for the operator is to bind it.
    """
    client, keys = scoped_app

    assert _get(client, keys["viewer_unbound"]).json() == []


def test_an_admin_sees_every_policy(scoped_app):
    """Scoping must not make the dashboard useless for the person running it."""
    client, keys = scoped_app

    rows = _get(client, keys["admin"]).json()

    assert {r["policy_id"] for r in rows} == {"policy-a", "policy-b"}


def test_stats_and_flows_are_scoped_too(scoped_app):
    """A count is a disclosure: it says how much traffic another tenant has."""
    client, keys = scoped_app

    assert _get(client, keys["viewer_a"], "/v1/logs/stats").json()["total"] == 1
    assert _get(client, keys["admin"], "/v1/logs/stats").json()["total"] == 2
    assert _get(client, keys["viewer_unbound"], "/v1/logs/stats").json()["total"] == 0


def test_no_response_field_carries_content(scoped_app):
    """The DTO is built field by field, so a column added later cannot start
    being returned because nobody updated the reader."""
    client, keys = scoped_app

    rows = _get(client, keys["admin"]).json()

    for row in rows:
        for gone in GONE:
            assert gone not in row, f"{gone} is still in the response DTO"


def test_the_writer_refuses_an_unscoped_row():
    """A null policy makes the row invisible to every viewer — a silent audit
    gap rather than a loud one."""
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.db.models import Base
    from app.interaction_log import InteractionLog

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)

    with pytest.raises(ValueError, match="policy_id is required"):
        InteractionLog(sessionmaker(bind=engine)).log_event(
            request_id="r",
            timestamp="2026-08-19T00:00:00Z",
            event_type="input",
            policy="p",
            policy_id="",
            blocked=False,
            transformed=False,
            latency_ms=1.0,
        )


def test_the_writer_has_no_parameter_for_content():
    """Removed rather than accepted and ignored.

    A parameter that is accepted and dropped is how a caller keeps believing
    content is stored, and how a later edit quietly reconnects it.
    """
    import inspect as _inspect

    from app.interaction_log import InteractionLog

    params = set(_inspect.signature(InteractionLog.log_event).parameters)

    assert not (params & set(GONE)), f"content parameters still accepted: {params & set(GONE)}"
