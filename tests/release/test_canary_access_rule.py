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

import pytest

from tests.release.expected_failures import GUARD_ROUTE
from tests.release.signatures import RECORDER, Signature

CANARY = "CANARY-ACCESS-RULE-NAME-7f22"
FORBIDDEN = "FORBIDDEN occurrence reached a surface"
CREATION_LOG = "app.services.access_rule_service:logger.info/created"
SUMMARY_SURFACE = f"{GUARD_ROUTE} -> $.summary"
RULES_SURFACE = f"{GUARD_ROUTE} -> $.result.access_rules[*] (key)"


BOOTSTRAP_KEY = "ak_release_gate_bootstrap_only_not_a_real_credential"


@pytest.fixture(scope="module")
def guarded(tmp_path_factory):
    """The PRODUCTION application with a blocking access rule installed.

    An earlier version called `evaluate_access_rules` and rebuilt `summary` and
    `result.access_rules` inside the test. A review set production's
    `GuardResult.access_rules={}` and every signature was still emitted -- so
    reconciliation could report an HTTP defect production no longer had.
    Both signatures are now derived by traversing the returned response.
    """
    import os

    import sqlalchemy as sa
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker

    from app.db.models import Policy, RuleSet
    from app.services.access_rule_service import AccessRuleService

    directory = tmp_path_factory.mktemp("access-rule-gate")
    os.environ["BOOTSTRAP_KEY"] = BOOTSTRAP_KEY
    os.environ["DB_URL"] = f"sqlite:///{directory}/gate.db"

    from app.main import create_app

    with TestClient(create_app(), raise_server_exceptions=False) as client:
        session = sessionmaker(bind=sa.create_engine(f"sqlite:///{directory}/gate.db"))()
        policy = session.query(Policy).first()
        rule_set = session.query(RuleSet).filter_by(policy_id=policy.id, event_type="input").first()
        AccessRuleService(session).create_rule(
            rule_set_id=rule_set.id,
            name=CANARY,
            conditions={"field": "model", "op": "==", "value": "deepseek"},
            then_action="block_and_stop",
        )
        session.commit()
        session.close()

        response = client.post(
            "/v1/guard_chat_completions",
            json={
                "guard_input": {"messages": [{"role": "user", "content": "hi"}]},
                "model": "deepseek",
            },
            headers={"Authorization": f"Bearer {BOOTSTRAP_KEY}"},
        )
        yield response


def test_the_request_was_blocked_by_the_rule(guarded):
    """The premise. If nothing blocked, neither surface is built at all."""
    assert guarded.status_code == 200, guarded.text
    body = guarded.json()
    assert body["result"]["blocked"] is True, body["result"]


def test_the_rule_name_reaches_the_guard_summary(guarded):
    """Record 2 of 3, read from the RESPONSE."""
    summary = guarded.json().get("summary", "")
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


def test_the_rule_name_is_a_key_in_the_result(guarded):
    """Record 3 of 3, read from the RESPONSE.

    `result.access_rules` is keyed BY RULE NAME, a distinct surface from the
    summary with its own collector path.
    """
    access_rules = guarded.json()["result"].get("access_rules") or {}
    if any(CANARY in str(key) for key in access_rules):
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


def test_the_two_surfaces_are_independent(guarded):
    """They are separate records because they are separate surfaces.

    A fix to one must not be credited to the other, so this asserts the value
    is present in each on its own terms.
    """
    body = guarded.json()
    assert CANARY in body.get("summary", "")
    assert any(CANARY in str(k) for k in (body["result"].get("access_rules") or {}))


def test_the_export_summary_is_deliberately_fixed():
    """The contrast that makes this a finding rather than a preference.

    Exports already get a fixed string for exactly this reason; the guard
    response does not.
    """
    import pathlib

    source = pathlib.Path("app/routes/guard.py").read_text()
    assert 'export_summary = "Blocked by access rule"' in source
