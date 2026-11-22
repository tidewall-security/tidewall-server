"""Populated prior-head SQLite migrations and legacy authentication."""

import sqlite3

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from app.auth.dependencies import require_role
from app.auth.key_utils import hash_key
from app.auth.middleware import AuthMiddleware
from app.db.engine import get_engine, get_session_factory
from tests.test_device_migration import _alembic

OLD = "fb6a694ad1fa"
NEW = "14e5a91c8b02"
TABLES = ("registration_tokens", "devices", "device_tombstones", "access_tokens", "device_refresh_tokens")


def test_populated_upgrade_authentication_and_downgrade(tmp_path):
    db = tmp_path / "legacy.db"
    _alembic(db, "upgrade", OLD)
    with sqlite3.connect(db) as con:
        con.execute("PRAGMA foreign_keys=ON")
        con.executescript("""
            INSERT INTO policies(id,name,type,report_only,is_default,created_at,updated_at)
            VALUES('p','p','application',0,0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
            INSERT INTO registration_tokens(id,name,token_hash,token_prefix,policy_id,created_at,expires_at)
            VALUES('rt','rt','rt-hash','rt_prefix','p',CURRENT_TIMESTAMP,'2099-01-01');
            INSERT INTO devices(id,installation_id,device_name,user_name,user_email,browser,os,ext_version,
                                policy_id,reg_token_id,status,last_seen,created_at)
            VALUES('d','i','d','u','','','','','p','rt','active',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
            INSERT INTO device_refresh_tokens(id,token_hash,device_id,expires_at,created_at)
            VALUES('dr','dr-hash','d','2099-01-01',CURRENT_TIMESTAMP);
            INSERT INTO device_tombstones(device_id,installation_id,reason,created_at)
            VALUES('gone','gone-installation','retired',CURRENT_TIMESTAMP);
        """)
        con.execute(
            "INSERT INTO access_tokens(id,token_hash,device_id,expires_at,created_at) "
            "VALUES('at',?,'d','2099-01-01',CURRENT_TIMESTAMP)",
            (hash_key("at_legacy"),),
        )
        original_rows = {table: con.execute(f"SELECT * FROM {table}").fetchall() for table in TABLES}
        original_schema = {table: con.execute(f"PRAGMA table_info({table})").fetchall() for table in TABLES}
        original_fks = {table: con.execute(f"PRAGMA foreign_key_list({table})").fetchall() for table in TABLES}
    _alembic(db, "upgrade", NEW)
    with sqlite3.connect(db) as con:
        assert con.execute("PRAGMA foreign_key_check").fetchall() == []
        assert con.execute("SELECT purpose, collector_approved_at FROM devices").fetchone() == ("guard_device", None)
        assert con.execute("SELECT purpose FROM registration_tokens").fetchone() == ("guard_device",)
        assert con.execute("SELECT purpose, collector_policy_id FROM device_tombstones").fetchone() == (
            "guard_device",
            None,
        )
        for table in ("devices", "registration_tokens", "device_tombstones"):
            for invalid in ("other", None):
                with pytest.raises(sqlite3.IntegrityError):
                    con.execute(f"UPDATE {table} SET purpose=?", (invalid,))
    engine = get_engine(f"sqlite:///{db}")
    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = get_session_factory(engine)

    @app.post("/v1/guard", dependencies=[Depends(require_role("api"))])
    def guard_probe(request: Request):
        return [request.state.device_id, request.state.policy_id]

    with TestClient(app) as client:
        assert client.post("/v1/guard", headers={"Authorization": "Bearer at_legacy"}).json() == ["d", "p"]
    engine.dispose()

    _alembic(db, "downgrade", OLD)
    with sqlite3.connect(db) as con:
        assert con.execute("PRAGMA foreign_key_check").fetchall() == []
        for table in TABLES:
            assert con.execute(f"PRAGMA table_info({table})").fetchall() == original_schema[table]
            assert con.execute(f"PRAGMA foreign_key_list({table})").fetchall() == original_fks[table]
            assert con.execute(f"SELECT * FROM {table}").fetchall() == original_rows[table]


def test_downgrade_cannot_convert_collectors_into_guard_registrations(tmp_path):
    db = tmp_path / "collector.db"
    _alembic(db, "upgrade", NEW)
    with sqlite3.connect(db) as con:
        con.execute(
            "INSERT INTO registration_tokens(id,name,token_hash,token_prefix,created_at,expires_at,purpose) "
            "VALUES('rt','rt','hash','rt_x',CURRENT_TIMESTAMP,'2099-01-01','collector_write')"
        )
    with pytest.raises(pytest.fail.Exception, match="collector identity"):
        _alembic(db, "downgrade", OLD)
    with sqlite3.connect(db) as con:
        assert con.execute("SELECT version_num FROM alembic_version").fetchone() == (NEW,)
        assert con.execute("SELECT purpose FROM registration_tokens").fetchone() == ("collector_write",)


def test_downgrade_refuses_tombstone_of_collector_whose_scope_was_lost(tmp_path):
    db = tmp_path / "unscoped.db"
    _alembic(db, "upgrade", NEW)
    engine = get_engine(f"sqlite:///{db}")
    from app.db.models import Device
    from app.services.device_service import DeviceService

    with get_session_factory(engine)() as session:
        device = Device(
            installation_id="fixture",
            device_name="d",
            user_name="",
            user_email="",
            purpose="collector_write",
            policy_id=None,
        )
        session.add(device)
        session.commit()
        DeviceService(session).delete_device(device.id)
    engine.dispose()
    with pytest.raises(pytest.fail.Exception, match="collector identity"):
        _alembic(db, "downgrade", OLD)
    with sqlite3.connect(db) as con:
        assert con.execute("SELECT version_num FROM alembic_version").fetchone() == (NEW,)
        assert con.execute("SELECT purpose, collector_policy_id FROM device_tombstones").fetchone() == (
            "collector_write",
            None,
        )


def test_collection_revision_preserves_populated_prior_head_and_enforces_scope(tmp_path):
    from uuid import uuid4

    from app.agent_events import Batch, Heartbeat
    from app.db.models import Policy
    from tests.test_agent_event_ingest import COLLECTION, DEVICE, NOW, VECTORS, batch, observation, provision

    db = tmp_path / "collection.db"
    _alembic(db, "upgrade", NEW)
    engine = get_engine(f"sqlite:///{db}")
    sessions = get_session_factory(engine)
    with sessions.begin() as session:
        session.add_all([Policy(id=p, name=p) for p in ["A", "B"]])
    _, first = provision(sessions)
    other = str(uuid4())
    _, second = provision(sessions, other)
    _alembic(db, "upgrade", "head")
    with sqlite3.connect(db) as con:
        assert con.execute("SELECT version_num FROM alembic_version").fetchone() == ("c81b0704d921",)
    from app.services.agent_event_service import heartbeat, ingest

    for principal in [first, second]:
        with sessions() as session:
            ingest(
                session,
                principal,
                Batch.model_validate(batch((1, observation()), device=principal.device_id)),
                lambda: NOW,
            )
    with sessions() as session:
        heartbeat(session, first, Heartbeat.model_validate_json(VECTORS["heartbeat"]), lambda: NOW)
    with sqlite3.connect(db) as con:
        con.execute("PRAGMA foreign_keys=ON")
        assert con.execute("PRAGMA foreign_key_check").fetchall() == []
        with pytest.raises(sqlite3.IntegrityError):
            con.execute(
                "UPDATE agent_observations SET session_id=(SELECT session_id FROM agent_sessions WHERE device_id=?) "
                "WHERE device_id=?",
                (other, DEVICE),
            )
        with pytest.raises(sqlite3.IntegrityError):
            con.execute("UPDATE agent_observations SET policy_id='B' WHERE device_id=?", (DEVICE,))
        with pytest.raises(sqlite3.IntegrityError):
            con.execute(
                "UPDATE collector_outcomes SET event_id=(SELECT event_id FROM agent_observations WHERE device_id=?) "
                "WHERE device_id=?",
                (other, DEVICE),
            )
        with pytest.raises(sqlite3.IntegrityError):
            con.execute(
                "INSERT INTO collector_outcomes SELECT device_id,ordinal,'other',outcome,reason,event_id,"
                "received_at,expires_at FROM collector_outcomes WHERE device_id=?",
                (DEVICE,),
            )
        con.execute("DELETE FROM devices WHERE id=?", (DEVICE,))
        assert all(
            con.execute(f"SELECT COUNT(*) FROM {t} WHERE device_id=?", (DEVICE,)).fetchone()[0] == 0 for t in COLLECTION
        )
        assert con.execute("SELECT COUNT(*) FROM agent_observations WHERE device_id=?", (other,)).fetchone() == (1,)
    _alembic(db, "downgrade", NEW)
    with sqlite3.connect(db) as con:
        assert con.execute("PRAGMA foreign_key_check").fetchall() == []
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert tables.isdisjoint(COLLECTION)
        assert con.execute("SELECT id,purpose,policy_id FROM devices").fetchall() == [(other, "collector_write", "A")]
    engine.dispose()
