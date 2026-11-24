import sqlite3

import pytest

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
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == ("b07f38a51d24",)
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


@pytest.mark.parametrize(
    ("encoding", "migrate"), [("UTF-8", True), ("UTF-16le", True), ("UTF-16be", True), ("UTF-16le", False)]
)
def test_issue_native_grant_respects_database_encoding(tmp_path, encoding, migrate):
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import text

    from app.auth.key_utils import hash_key
    from app.db.models import Base, RuleSet
    from app.native_prompt import NativeGrantRequest, NativePolicySettings
    from app.services.native_prompt_grants import authorize_native, configure_native, issue_native_grant

    db = tmp_path / "encoded.db"
    with sqlite3.connect(db) as conn:
        conn.execute(f"PRAGMA encoding='{encoding}'")
        # Persist the selected SQLite file encoding before Alembic opens its own connection.
        conn.executescript("CREATE TABLE initialize_encoding (id INTEGER); DROP TABLE initialize_encoding;")
    engine = get_engine(f"sqlite:///{db}")
    sessions = get_session_factory(engine)
    if migrate:
        _alembic(db, "upgrade", "c81b0704d921")
    else:
        Base.metadata.create_all(engine)
    with sessions.begin() as session:
        session.add(Policy(id="A", name="A"))
        session.flush()
        session.add(RuleSet(policy_id="A", event_type="input", detectors={"malicious_prompt": {"action": "block"}}))
    _, collector = provision(sessions)
    if migrate:
        _alembic(db, "upgrade", "9a42c7d3e601")
    at = datetime(2026, 1, 2, 12, 0, 0, 123456, tzinfo=UTC)
    with sessions.begin() as session:
        session.execute(text("BEGIN IMMEDIATE"))
        configure_native(session, "A", NativePolicySettings(enabled=True), "A")
    with sessions.begin() as session:
        session.execute(text("BEGIN IMMEDIATE"))
        grant = issue_native_grant(
            session,
            NativeGrantRequest(
                device_id=DEVICE,
                session_token="a" * 64,
                native_profile="claude-code.user-prompt-submit.1",
                ttl_seconds=60,
            ),
            "A",
            now=at,
        )
    assert grant.expires_at == (at + timedelta(seconds=60)).isoformat()
    with sessions.begin() as session:
        principal = authorize_native(session, collector.token_hash, hash_key(grant.capability), now=at)
        assert principal.grant_id == grant.grant_id
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA encoding").fetchone() == (encoding,)
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        for column in ("grant_id", "session_token", "capability_hash", "issued_at", "expires_at"):
            with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
                conn.execute(f"UPDATE native_prompt_grants SET {column}={column}||char(0)||'extra'")
    engine.dispose()


def test_delivery_lookup_and_cascade_plans_after_existing_native_head(tmp_path):
    db = tmp_path / "delivery-index.db"
    index = "ix_native_prompt_deliveries_decision_id"
    _alembic(db, "upgrade", "9a42c7d3e601")
    _alembic(db, "upgrade", "head")
    with sqlite3.connect(db) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        for sql in (
            "SELECT stage FROM native_prompt_deliveries WHERE decision_id IN ('a','b') "
            "AND expires_at>CURRENT_TIMESTAMP",
            "DELETE FROM native_prompt_decisions WHERE decision_id='a'",
        ):
            plan = [row[3] for row in conn.execute("EXPLAIN QUERY PLAN " + sql)]
            assert any("SEARCH native_prompt_deliveries" in line and index in line for line in plan), plan
    _alembic(db, "downgrade", "9a42c7d3e601")
    with sqlite3.connect(db) as conn:
        assert index not in [row[1] for row in conn.execute("PRAGMA index_list(native_prompt_deliveries)")]
