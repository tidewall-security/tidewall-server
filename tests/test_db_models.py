"""Tests for SQLAlchemy ORM models."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.engine import get_engine, get_session_factory


@pytest.fixture
def db_session():
    """Create an in-memory database with all tables."""
    from app.db.models import Base

    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = get_session_factory(engine)
    session = SessionLocal()
    yield session
    session.close()


def test_create_policy(db_session):
    from app.db.models import Policy

    policy = Policy(
        name="test-policy",
        type="application",
        description="A test policy",
        report_only=False,
        is_default=True,
    )
    db_session.add(policy)
    db_session.commit()

    result = db_session.query(Policy).filter_by(name="test-policy").first()
    assert result is not None
    assert result.type == "application"
    assert result.is_default is True
    assert result.id is not None


def test_create_rule_set_linked_to_policy(db_session):
    from app.db.models import Policy, RuleSet

    policy = Policy(name="p1", type="application")
    db_session.add(policy)
    db_session.commit()

    rule_set = RuleSet(
        policy_id=policy.id,
        event_type="input",
        detectors={"malicious_prompt": {"enabled": True, "action": "block"}},
    )
    db_session.add(rule_set)
    db_session.commit()

    assert rule_set.id is not None
    assert rule_set.policy_id == policy.id

    db_session.refresh(policy)
    assert len(policy.rule_sets) == 1


def test_create_api_key(db_session):
    from app.db.models import APIKey, Policy

    policy = Policy(name="p1", type="application", is_default=True)
    db_session.add(policy)
    db_session.commit()

    key = APIKey(
        name="test-collector",
        key_hash="abc123hash",
        key_prefix="ak_abc1",
        role="api",
        policy_id=policy.id,
        collector_type="application",
    )
    db_session.add(key)
    db_session.commit()

    assert key.id is not None
    assert key.policy_id == policy.id


def test_create_interaction(db_session):
    from app.db.models import Interaction

    interaction = Interaction(
        request_id="tw_test123",
        timestamp="2026-03-28T12:00:00Z",
        event_type="input",
        policy_id="some-policy-id",
        policy_name="test-policy",
        blocked=True,
        transformed=False,
        latency_ms=150.5,
        summary="malicious_prompt: blocked",
    )
    db_session.add(interaction)
    db_session.commit()

    assert interaction.id is not None
    assert interaction.blocked is True


def test_create_vault(db_session):
    from datetime import datetime, timezone

    from app.db.models import Vault

    vault = Vault(
        data=b"pickled-vault-data",
        expires_at=datetime(2026, 3, 28, 13, 0, 0, tzinfo=timezone.utc),
    )
    db_session.add(vault)
    db_session.commit()

    assert vault.id is not None


def test_create_activity_log(db_session):
    from app.db.models import ActivityLog

    entry = ActivityLog(
        actor="admin",
        action="update",
        target_type="policy",
        target_id="some-id",
        old_value={"action": "report"},
        new_value={"action": "block"},
    )
    db_session.add(entry)
    db_session.commit()

    assert entry.id is not None


def test_access_rule_linked_to_rule_set(db_session):
    from app.db.models import AccessRule, Policy, RuleSet

    policy = Policy(name="p1", type="application")
    db_session.add(policy)
    db_session.commit()

    rs = RuleSet(policy_id=policy.id, event_type="input", detectors={})
    db_session.add(rs)
    db_session.commit()

    rule = AccessRule(
        rule_set_id=rs.id,
        name="block deepseek",
        conditions={"model.model_name": {"==": "deepseek"}},
        then_action="block_and_stop",
        else_action="continue",
        sort_order=0,
    )
    db_session.add(rule)
    db_session.commit()

    db_session.refresh(rs)
    assert len(rs.access_rules) == 1
    assert rs.access_rules[0].name == "block deepseek"


def test_policy_cascade_deletes_rule_sets(db_session):
    from app.db.models import Policy, RuleSet

    policy = Policy(name="p1", type="application")
    db_session.add(policy)
    db_session.commit()

    rs = RuleSet(policy_id=policy.id, event_type="input", detectors={})
    db_session.add(rs)
    db_session.commit()

    db_session.delete(policy)
    db_session.commit()

    assert db_session.query(RuleSet).count() == 0
