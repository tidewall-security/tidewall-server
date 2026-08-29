"""Detector matches must actually arrive in the capture column.

Capture was wired end to end and stored nothing. A detector knows itself by its
class's `name`; the scanner opens its capture batch under the key the POLICY
registers it by. For most detectors those differ -- `pii` against
`confidential_and_pii_entity` -- and the mismatch failed validation, poisoned
the batch, and discarded every match that detector found. At debug level.

`custom_entity` matched by coincidence, its class name and policy key being the
same string, which is why capture appeared to work at all and why the tests that
existed did not notice: they built `matches_json` themselves and asserted on
what they had put there.

This is the release gate's capability cause, which its manifest recorded 245
times -- 5 detector families x 7 representations x 7 surfaces of a single
defect.
"""

from __future__ import annotations

import pytest

from app.db.models import InteractionContent, Policy, RuleSet

from .test_guard_routes import _make_app_and_client

EMAIL = "jon@example.com"


@pytest.fixture
def capturing():
    client, _admin, api_key, _viewer, session_factory = _make_app_and_client()
    with session_factory() as session:
        policy = session.query(Policy).filter_by(is_default=True).one()
        policy.raw_content_enabled = True
        rule_set = session.query(RuleSet).filter_by(policy_id=policy.id, event_type="input").one()
        rule_set.detectors = {
            "confidential_and_pii_entity": {
                "enabled": True,
                "action": "redact",
                "entity_types": ["EMAIL_ADDRESS"],
            }
        }
        session.commit()
    return client, api_key, session_factory


def _guard(client, api_key, content):
    return client.post(
        "/v1/guard_chat_completions",
        json={"guard_input": {"messages": [{"role": "user", "content": content}]}, "event_type": "input"},
        headers={"Authorization": f"Bearer {api_key}"},
    )


def test_a_detected_value_reaches_the_capture_column(capturing):
    """The whole point of capture. Every part of this worked except the last."""
    client, api_key, session_factory = capturing
    response = _guard(client, api_key, f"mail {EMAIL} ok")
    assert response.status_code == 200
    assert response.json()["result"]["transformed"] is True, "nothing was detected, so this proves nothing"

    with session_factory() as session:
        rows = session.query(InteractionContent).all()
        assert rows, "capture is on and no content row was written"
        matches = rows[0].matches_json["matches"]

    assert matches, "the detector found a value and the capture column is empty"
    assert matches[0]["value"] == EMAIL
    assert matches[0]["match_type"] == "EMAIL_ADDRESS"


def test_the_match_is_attributed_to_the_detector_the_policy_names(capturing):
    """Not to the detector's own class name.

    Two names existed for one detector and the capture recorded neither
    reliably. Anything reading this column joins on the policy's key, which is
    what appears in `detectors` in the response and in every export.
    """
    client, api_key, session_factory = capturing
    _guard(client, api_key, f"mail {EMAIL} ok")
    with session_factory() as session:
        matches = session.query(InteractionContent).one().matches_json["matches"]
    assert matches[0]["detector"] == "confidential_and_pii_entity"


def test_the_match_is_attributed_to_the_message_it_came_from(capturing):
    """A span is resolved back to one message, so evidence points somewhere."""
    client, api_key, session_factory = capturing
    client.post(
        "/v1/guard_chat_completions",
        json={
            "guard_input": {
                "messages": [
                    {"role": "system", "content": "be helpful"},
                    {"role": "user", "content": f"mail {EMAIL} ok"},
                ]
            },
            "event_type": "input",
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )
    with session_factory() as session:
        matches = session.query(InteractionContent).one().matches_json["matches"]
    assert matches[0]["source"]["index"] == 1, "attributed to the wrong message"
    assert matches[0]["source"]["field"] == "content"


def test_capture_off_stores_nothing(capturing):
    """The column is only written when the policy asks for it. Without this,
    always capturing would satisfy every test above."""
    client, api_key, session_factory = capturing
    with session_factory() as session:
        session.query(Policy).filter_by(is_default=True).one().raw_content_enabled = False
        session.commit()
    _guard(client, api_key, f"mail {EMAIL} ok")
    with session_factory() as session:
        assert session.query(InteractionContent).count() == 0
