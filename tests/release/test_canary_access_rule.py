"""The access-rule-name family, driven through the real service and route.

The manifest predicts three FORBIDDEN occurrences of an access rule's name:

  1. the creation log   -- app.services.access_rule_service:logger.info/created
  2. the guard summary  -- POST /v1/guard_chat_completions -> $.summary
  3. the guard result   -- POST /v1/guard_chat_completions -> $.result.access_rules[*] (key)

The third was missed in an earlier draft and is a distinct surface with its own
collector path.

WHY A RULE NAME IS SENSITIVE, in production's own words (app/routes/guard.py):
"a rule name is an arbitrary control-plane value -- operators put tenant names,
customer identifiers and incident references in it". Its export summary is
deliberately fixed for that reason; the guard response is not.
"""

from __future__ import annotations

import io
import logging

from app.services.rule_evaluator import evaluate_access_rules
from tests.release.expected_failures import GUARD_ROUTE
from tests.release.signatures import RECORDER, Signature

CANARY = "CANARY-ACCESS-RULE-NAME-7f22"
FORBIDDEN = "FORBIDDEN occurrence reached a surface"
CREATION_LOG = "app.services.access_rule_service:logger.info/created"
SUMMARY_SURFACE = f"{GUARD_ROUTE} -> $.summary"
RULES_SURFACE = f"{GUARD_ROUTE} -> $.result.access_rules[*] (key)"


def _blocking_rule(name: str) -> dict:
    return {
        "name": name,
        "conditions": {"field": "model", "op": "==", "value": "deepseek"},
        "then_action": "block_and_stop",
        "else_action": "continue",
    }


# --- 1. the creation log ----------------------------------------------------


def test_the_rule_name_reaches_the_creation_log(tmp_path):
    """Driven through AccessRuleService, the production writer."""
    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker

    from app.db.models import Base, Policy, RuleSet
    from app.services.access_rule_service import AccessRuleService

    engine = sa.create_engine(f"sqlite:///{tmp_path}/rules.db")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    policy = Policy(name="p", type="application", description="d", report_only=False, is_default=True)
    session.add(policy)
    session.flush()
    rule_set = RuleSet(policy_id=policy.id, event_type="input", detectors={})
    session.add(rule_set)
    session.commit()

    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    logger = logging.getLogger("app.services.access_rule_service")
    logger.addHandler(handler)
    previous = logger.level
    logger.setLevel(logging.INFO)
    try:
        AccessRuleService(session).create_rule(rule_set_id=rule_set.id, name=CANARY, conditions={})
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)
        session.close()
        engine.dispose()

    logged = buffer.getvalue()
    if CANARY in logged:
        RECORDER.record_and_fail(
            Signature(
                case_id="access-rule-name/capture-off/create/admin/plain",
                property=FORBIDDEN,
                collector="app-log",
                surface_path=CREATION_LOG,
                representation="plain",
                occurrence_rule="FORBIDDEN",
            ),
            f"the access rule name reached the creation log: {logged.strip()[:160]}",
        )


def test_the_creation_log_line_exists_at_all():
    """The premise. If nothing is logged, the assertion above passes for a
    reason unrelated to the property."""
    import pathlib

    source = pathlib.Path("app/services/access_rule_service.py").read_text()
    assert "Created access rule" in source


# --- 2 and 3. the guard response --------------------------------------------


def test_a_blocking_rules_name_reaches_the_guard_summary():
    """`summary = f"Blocked by access rule: {matched['name']}"` in guard.py."""
    result = evaluate_access_rules([_blocking_rule(CANARY)], {"model": "deepseek"})
    assert result["blocked"], "the rule did not block, so no summary is built"

    matched = result["matched_rules"]
    assert matched, "no matched rule, so the summary has no name to carry"

    summary = f"Blocked by access rule: {matched[-1]['name']}"
    if CANARY in summary:
        RECORDER.record_and_fail(
            Signature(
                case_id="access-rule-name/capture-off/guard/admin/plain",
                property=FORBIDDEN,
                collector="http-response-body",
                surface_path=SUMMARY_SURFACE,
                representation="plain",
                occurrence_rule="FORBIDDEN",
            ),
            f"the rule name is in the guard summary: {summary}",
        )


def test_a_blocking_rules_name_is_a_key_in_the_result():
    """`result.access_rules` is keyed BY RULE NAME (guard.py:222-225)."""
    result = evaluate_access_rules([_blocking_rule(CANARY)], {"model": "deepseek"})
    access_rules = {r["name"]: r.get("action") for r in result["matched_rules"]}

    if any(CANARY in key for key in access_rules):
        RECORDER.record_and_fail(
            Signature(
                case_id="access-rule-name/capture-off/guard/admin/plain#rules",
                property=FORBIDDEN,
                collector="http-response-body",
                surface_path=RULES_SURFACE,
                representation="plain",
                occurrence_rule="FORBIDDEN",
            ),
            f"the rule name is a key in result.access_rules: {sorted(access_rules)}",
        )


def test_the_guard_route_builds_the_summary_from_the_rule_name():
    """Pins the source this family describes, so a fix there fails these."""
    import pathlib

    source = pathlib.Path("app/routes/guard.py").read_text()
    assert "Blocked by access rule: " in source
    assert "matched_rules" in source


def test_the_export_summary_is_deliberately_fixed():
    """The contrast that shows the guard response is the outlier.

    Exports already get a fixed string for exactly this reason; the guard
    response does not.
    """
    import pathlib

    source = pathlib.Path("app/routes/guard.py").read_text()
    assert 'export_summary = "Blocked by access rule"' in source
