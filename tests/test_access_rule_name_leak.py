"""An access rule's name must not leave the control plane.

A rule name is arbitrary operator text. The reasoning is already written twice
in this codebase -- `app/services/export_service.py` and the removed `summary`
column in `app/db/models.py` -- and both say the same thing: operators put
tenant names, customer identifiers and incident references in them.

It was removed from storage and from exports, and left in the two places that
reach the caller: the guard response `summary`, and the `access_rules` map,
whose KEY was the rule name. The response is the worst of the three. An export
goes to the operator's own SIEM; the response goes to whoever called the guard,
who is frequently an end user reading it in a browser and has no relationship
with the operator's naming scheme.

These are the release gate's `access-rule-name` records.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.db.models import AccessRule, Policy, RuleSet
from app.validation_errors import install

from .test_guard_routes import _make_app_and_client

#: Stands in for the tenant name or incident reference an operator would use.
CANARY = "project-hollowpoint-acquisition"


@pytest.fixture
def blocked():
    client, _admin, api_key, _viewer, session_factory = _make_app_and_client()
    install(client.app)
    with session_factory() as session:
        policy = session.query(Policy).filter_by(is_default=True).one()
        rule_set = session.query(RuleSet).filter_by(policy_id=policy.id, event_type="input").one()
        session.add_all(
            [
                AccessRule(
                    rule_set_id=rule_set.id,
                    name=CANARY,
                    conditions={"field": "app_id", "op": "==", "value": "blocked-app"},
                    then_action="block_and_stop",
                    else_action="continue",
                    sort_order=1,
                ),
                # Matches and does NOT stop, so it lands in `matched_rules` on a
                # request that is allowed through. Without it the allowed-path
                # test cannot observe anything: an unmatched rule contributes no
                # entry, so the map is empty and passes whether or not the key
                # is the rule name.
                AccessRule(
                    rule_set_id=rule_set.id,
                    name=f"{CANARY}-observer",
                    conditions={"field": "app_id", "op": "!=", "value": "\x00never"},
                    then_action="continue",
                    else_action="continue",
                    sort_order=0,
                ),
            ]
        )
        session.commit()
    return TestClient(client.app, raise_server_exceptions=False), api_key


def _guard(client, api_key, app_id):
    return client.post(
        "/v1/guard_chat_completions",
        json={
            "guard_input": {"messages": [{"role": "user", "content": "hello"}]},
            "event_type": "input",
            "app_id": app_id,
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )


def test_a_blocked_response_does_not_carry_the_rule_name(blocked):
    client, api_key = blocked
    response = _guard(client, api_key, "blocked-app")
    assert response.status_code == 200
    assert response.json()["result"]["blocked"] is True, "the rule did not fire, so this proves nothing"
    assert CANARY not in response.text


def test_an_allowed_response_does_not_carry_it_either(blocked):
    """The map is built at two sites. Fixing only the blocked one would leave
    the name in every response that was NOT blocked, which is most of them."""
    client, api_key = blocked
    response = _guard(client, api_key, "some-other-app")
    assert response.status_code == 200
    assert CANARY not in response.text


def test_the_caller_is_still_told_it_was_blocked(blocked):
    """Removing the name must not cost the caller the reason.

    Without this, emptying the summary entirely would satisfy the tests above.
    """
    client, api_key = blocked
    body = _guard(client, api_key, "blocked-app").json()
    assert body["result"]["blocked"] is True
    assert "access rule" in body["summary"].lower()


def test_creating_a_rule_does_not_log_its_name(caplog):
    """The application log is shipped, aggregated and searched far more widely
    than the control plane that set the name."""
    import logging

    client, _admin, _api, _viewer, session_factory = _make_app_and_client()
    with session_factory() as session:
        policy = session.query(Policy).filter_by(is_default=True).one()
        rule_set = session.query(RuleSet).filter_by(policy_id=policy.id, event_type="input").one()
        from app.services.access_rule_service import AccessRuleService

        with caplog.at_level(logging.INFO):
            rule = AccessRuleService(session).create_rule(
                rule_set_id=rule_set.id,
                name=CANARY,
                conditions={"field": "app_id", "op": "==", "value": "x"},
                then_action="block_and_stop",
            )
    assert caplog.text, "nothing was logged, so this proves nothing"
    assert CANARY not in caplog.text
    assert rule.id in caplog.text, "the log must still say WHICH rule"
