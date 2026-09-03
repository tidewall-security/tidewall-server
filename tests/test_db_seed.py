"""Tests for first-boot policy seeding."""

import pytest

from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, Policy, RuleSet


@pytest.fixture
def empty_db():
    """Create an in-memory database with tables but no data."""
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = get_session_factory(engine)
    session = Session()
    yield session
    session.close()


def test_seed_creates_default_policy(empty_db):
    from app.db.seed import seed_from_yaml

    seed_from_yaml(empty_db, "policy.yaml")

    policies = empty_db.query(Policy).all()
    assert len(policies) == 1
    assert policies[0].name == "default_policy"
    assert policies[0].is_default is True


def test_seed_creates_a_rule_set_for_every_event_type(empty_db):
    """The set is pinned, not sampled.

    The previous version of this asserted only that "input" and "output" were
    present, which passes for any superset -- so it never noticed that three
    event types the schema accepts had no rule set at all, and that the guard
    was silently falling back to the input engine for all of them.

    Equality against EVENT_TYPES rather than a restated tuple means a sixth
    event type fails here on the day it is added, not a day later.
    """
    from app.db.seed import seed_from_yaml
    from app.models import EVENT_TYPES

    seed_from_yaml(empty_db, "policy.yaml")

    policy = empty_db.query(Policy).first()
    rule_sets = empty_db.query(RuleSet).filter_by(policy_id=policy.id).all()
    assert {rs.event_type for rs in rule_sets} == set(EVENT_TYPES)


def test_seeded_tool_rule_sets_carry_no_report_only_or_access_rules(empty_db):
    """Copying detectors is behaviour-preserving; copying the row is not.

    get_engine reads only rs.detectors and takes report_only from the policy,
    while the route reads the requested event type's own row for access rules
    and its report_only override -- and today finds nothing, because the row is
    absent. So the new rows must inherit detectors and nothing else, or tool
    events would newly acquire input's access rules and could block before any
    detector runs.
    """
    from app.db.seed import seed_from_yaml

    seed_from_yaml(empty_db, "policy.yaml")

    policy = empty_db.query(Policy).first()
    inp = empty_db.query(RuleSet).filter_by(policy_id=policy.id, event_type="input").one()
    for et in ("tool_input", "tool_output", "tool_listing"):
        rs = empty_db.query(RuleSet).filter_by(policy_id=policy.id, event_type=et).one()
        # The same detectors are configured; individual values may differ where
        # an event override applies, which is the point of event_overrides.
        assert set(rs.detectors) == set(inp.detectors), f"{et} should configure the same detectors"
        assert rs.report_only is None, f"{et} must not inherit a report_only override"
        assert rs.access_rules == [], f"{et} must not inherit access rules"


def test_seed_detectors_populated(empty_db):
    from app.db.seed import seed_from_yaml

    seed_from_yaml(empty_db, "policy.yaml")

    rs = empty_db.query(RuleSet).filter_by(event_type="input").first()
    assert rs.detectors is not None
    assert "malicious_prompt" in rs.detectors


def test_seed_skips_if_policies_exist(empty_db):
    """Seed should not overwrite existing policies."""
    existing = Policy(name="existing", type="application", is_default=True)
    empty_db.add(existing)
    empty_db.commit()

    from app.db.seed import seed_from_yaml

    seed_from_yaml(empty_db, "policy.yaml")

    policies = empty_db.query(Policy).all()
    assert len(policies) == 1
    assert policies[0].name == "existing"


def test_event_overrides_are_applied_per_event_type(empty_db):
    """Per-surface thresholds are expressed in policy.yaml, not hidden in code.

    The injection classifier ran at one threshold on every surface, and its
    false positives concentrate almost entirely on tool_output. Fixing that
    needs a different threshold per surface -- and a threshold that lives only
    in seeding code would not be visible to an operator reading the policy.
    """
    from app.db.seed import seed_from_yaml

    seed_from_yaml(empty_db, "policy.yaml")

    policy = empty_db.query(Policy).first()

    def threshold(event_type):
        rs = empty_db.query(RuleSet).filter_by(policy_id=policy.id, event_type=event_type).one()
        return rs.detectors["malicious_prompt"]["threshold"]

    assert threshold("input") == 0.9, "input keeps the base threshold"
    assert threshold("output") == 0.975
    assert threshold("tool_output") == 0.98
    # An event type with no override inherits the base block unchanged.
    # Tool definitions are scanned field by field, and a description is an
    # imperative sentence -- the grammar the classifier reads as an
    # instruction. Raised to cut that false-positive class.
    assert threshold("tool_listing") == 0.99


def test_an_override_for_an_unknown_event_type_is_refused(empty_db, tmp_path):
    """The override section is validated, not merely read.

    An unrecognised event type here would silently configure nothing, which is
    the accepted-but-not-honoured pattern this codebase keeps finding.
    """
    import yaml

    from app.db.seed import seed_from_yaml

    base = yaml.safe_load(open("policy.yaml"))
    base["event_overrides"] = {"not_an_event_type": {"malicious_prompt": {"threshold": 0.5}}}
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump(base))

    with pytest.raises(ValueError, match="event_overrides"):
        seed_from_yaml(empty_db, str(p))
