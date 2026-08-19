"""Tests for AccessRuleService — CRUD operations."""

import pytest
from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, Policy, RuleSet, AccessRule


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = get_session_factory(engine)
    session = Session()
    # Seed a policy with input rule set
    policy = Policy(name="test", type="application", is_default=True)
    session.add(policy)
    session.flush()
    rs = RuleSet(policy_id=policy.id, event_type="input", detectors={})
    session.add(rs)
    session.commit()
    yield session
    session.close()


def _get_rule_set_id(session):
    return session.query(RuleSet).first().id


def test_create_access_rule(db_session):
    from app.services.access_rule_service import AccessRuleService

    svc = AccessRuleService(db_session)
    rule = svc.create_rule(
        rule_set_id=_get_rule_set_id(db_session),
        name="block deepseek",
        conditions={"field": "model.model_name", "op": "==", "value": "deepseek"},
        then_action="block_and_stop",
        else_action="continue",
    )
    assert rule.id is not None
    assert rule.name == "block deepseek"
    assert rule.sort_order == 0


def test_create_multiple_rules_increments_sort_order(db_session):
    from app.services.access_rule_service import AccessRuleService

    svc = AccessRuleService(db_session)
    rs_id = _get_rule_set_id(db_session)
    r1 = svc.create_rule(rs_id, name="rule1", conditions={}, then_action="continue", else_action="continue")
    r2 = svc.create_rule(rs_id, name="rule2", conditions={}, then_action="continue", else_action="continue")
    assert r1.sort_order == 0
    assert r2.sort_order == 1


def test_list_rules_ordered(db_session):
    from app.services.access_rule_service import AccessRuleService

    svc = AccessRuleService(db_session)
    rs_id = _get_rule_set_id(db_session)
    svc.create_rule(rs_id, name="second", conditions={}, then_action="continue", else_action="continue")
    svc.create_rule(rs_id, name="first", conditions={}, then_action="continue", else_action="continue")
    rules = svc.list_rules(rs_id)
    assert len(rules) == 2
    assert rules[0].sort_order <= rules[1].sort_order


def test_update_rule(db_session):
    from app.services.access_rule_service import AccessRuleService

    svc = AccessRuleService(db_session)
    rule = svc.create_rule(
        _get_rule_set_id(db_session),
        name="orig",
        conditions={},
        then_action="continue",
        else_action="continue",
    )
    updated = svc.update_rule(rule.id, name="renamed", then_action="block_and_stop")
    assert updated.name == "renamed"
    assert updated.then_action == "block_and_stop"


def test_delete_rule(db_session):
    from app.services.access_rule_service import AccessRuleService

    svc = AccessRuleService(db_session)
    rule = svc.create_rule(
        _get_rule_set_id(db_session),
        name="deletable",
        conditions={},
        then_action="continue",
        else_action="continue",
    )
    svc.delete_rule(rule.id)
    assert db_session.query(AccessRule).filter_by(id=rule.id).first() is None
