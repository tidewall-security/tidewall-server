import sqlite3

from app.db.engine import get_engine, get_session_factory
from app.db.models import Policy
from tests.test_agent_event_ingest import DEVICE, provision
from tests.test_device_migration import _alembic

TABLES = {
    "native_prompt_" + t for t in ("policy_configs", "grants", "observations", "decisions", "assessments", "deliveries")
}


def test_prior_collector_survives_native_upgrade_and_downgrade(tmp_path):
    db = tmp_path / "native.db"
    _alembic(db, "upgrade", "c81b0704d921")
    engine = get_engine(f"sqlite:///{db}")
    sessions = get_session_factory(engine)
    with sessions.begin() as s:
        s.add(Policy(id="A", name="A"))
    _, p = provision(sessions, DEVICE)
    engine.dispose()
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO agent_sessions VALUES(?,?,?,?,?,CURRENT_TIMESTAMP)",
            ("session", DEVICE, "A", "claude-code", "a" * 64),
        )
        before = conn.execute("SELECT * FROM access_tokens").fetchall()
    _alembic(db, "upgrade", "head")
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == ("9a42c7d3e601",)
        assert TABLES <= {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("SELECT COUNT(*) FROM native_prompt_grants").fetchone() == (0,)
    _alembic(db, "downgrade", "c81b0704d921")
    with sqlite3.connect(db) as conn:
        assert TABLES.isdisjoint(r[0] for r in conn.execute("SELECT name FROM sqlite_master"))
        assert conn.execute("SELECT * FROM access_tokens").fetchall() == before
        assert conn.execute("SELECT purpose,id FROM devices").fetchone() == ("collector_write", p.device_id)
        assert conn.execute("SELECT session_id FROM agent_sessions").fetchone() == ("session",)
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_scoped_parents_and_closed_evidence_checks_on_migrated_storage(tmp_path):
    from datetime import UTC, datetime, timedelta
    from uuid import uuid4

    import pytest
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    from app.db.models import (
        AgentSession,
        NativePromptAssessment,
        NativePromptDecision,
        NativePromptDelivery,
        NativePromptGrant,
        NativePromptObservation,
        NativePromptPolicyConfig,
    )
    from app.native_prompt import MODEL_IDENTITY_JSON

    path = tmp_path / "constraints.db"
    _alembic(path, "upgrade", "head")
    engine = get_engine(f"sqlite:///{path}")
    sessions = get_session_factory(engine)
    now = datetime.now(UTC)

    def uid():
        return str(uuid4())

    with sessions.begin() as db:
        db.add(Policy(id="A", name="A"))
    provision(sessions)
    with sessions.begin() as db:
        db.add(NativePromptPolicyConfig(policy_id="A", generation=1))
        link = AgentSession(
            device_id=DEVICE, policy_id="A", agent="claude-code", native_session_token="a" * 64, received_at=now
        )
        db.add(link)
        db.flush()
        scope = dict(device_id=DEVICE, policy_id="A", session_token="a" * 64)
        grant = NativePromptGrant(
            **scope,
            session_id=link.session_id,
            capture_allowed=True,
            grant_generation=1,
            policy_generation=1,
            issued_at=now,
            expires_at=now + timedelta(seconds=1800),
            capability_hash="c" * 64,
            native_profile="claude-code.user-prompt-submit.1",
        )
        obs = NativePromptObservation(
            **scope,
            session_id=link.session_id,
            agent="claude-code",
            agent_version="2.1.330",
            native_profile="claude-code.user-prompt-submit.1",
            occurrence_id=uid(),
            received_at=now,
            expires_at=now + timedelta(days=30),
        )
        db.add_all([grant, obs])
        db.flush()
        binding = dict(request_id=uid(), occurrence_id=obs.occurrence_id, grant_id=grant.grant_id, grant_generation=1)
        decision = NativePromptDecision(
            **scope,
            **binding,
            session_id=link.session_id,
            event_id=obs.event_id,
            policy_generation=1,
            policy_revision="a" * 64,
            mode="enforce",
            input_state="complete",
            process_id=uid(),
            received_at=now,
            expires_at=obs.expires_at,
        )
        db.add(decision)
        db.flush()
        db.add(
            NativePromptAssessment(
                decision_id=decision.decision_id,
                device_id=DEVICE,
                policy_id="A",
                status="assessed",
                reason="clean",
                profile="tidewall.prompt-injection.1",
                model_identity=MODEL_IDENTITY_JSON,
                unsafe_score=0.1,
                score_kind="two_class_softmax_uncalibrated",
                input_tokens=25,
            )
        )
        db.add(
            NativePromptDelivery(
                decision_id=decision.decision_id,
                device_id=DEVICE,
                policy_id="A",
                **binding,
                report_id=uid(),
                stage="stdout_flushed",
                evidence_source="hook",
                received_at=now,
                expires_at=obs.expires_at,
            )
        )
    # A full 1,800 seconds across UTC midnight is valid down to the last microsecond.
    with sessions.begin() as db:
        db.execute(
            text(
                "UPDATE native_prompt_grants SET issued_at='2028-02-29 23:45:00.999999', "
                "expires_at='2028-03-01 00:15:00.999999'"
            )
        )
    for table, assignment in [
        ("deliveries", "report_id=report_id || char(0) || 'extra'"),
        ("grants", "capability_hash=capability_hash || char(0) || 'extra'"),
        ("grants", "issued_at='2026-01-01 12:00:00+06:00',expires_at='2026-01-01 12:30:00-06:00'"),
        ("grants", "issued_at='2026-02-30 11:00:00.000000',expires_at='2026-02-30 11:30:00.000000'"),
        ("grants", "issued_at='2026-01-01 12:00:00.000000',expires_at='2026-01-01 12:30:00.000001'"),
        ("grants", "session_token='" + "b" * 64 + "'"),
        ("observations", "session_token='" + "b" * 64 + "'"),
        ("deliveries", "report_id='raw-free-text'"),
        ("grants", "expires_at=datetime(issued_at,'+1801 seconds')"),
        ("decisions", "policy_generation=2"),
        ("decisions", "reason='clean'"),
        ("decisions", "process_id='raw-free-text'"),
        ("assessments", "status='failed'"),
        ("assessments", "model_identity='wrong-model'"),
        ("assessments", "unsafe_score=1.01"),
        ("assessments", "input_tokens=1025"),
        ("deliveries", "stage='arbitrary'"),
        ("deliveries", "token_count=-1"),
        ("deliveries", "marker_present=7"),
        ("deliveries", "grant_generation=2"),
    ]:
        with sessions.begin() as db, pytest.raises(IntegrityError):
            db.execute(text(f"UPDATE native_prompt_{table} SET {assignment}"))
    engine.dispose()
