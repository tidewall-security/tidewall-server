"""The guard response must not carry exact matched values (P0-6 step 3b).

`GuardResult.detectors` was the raw detector payload, so a response returned
custom_entity's matched value and its start_pos, and malicious_entity's
unmodified URL, to every caller.

The caller supplied the content, so this is not disclosure to a new party. It
still matters because a response body fans out further than the request did:
proxies, APM tools, browser devtools and the caller's own logging all see it,
and the caller acts on `guard_output`, not on exact values.
"""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.auth.middleware import AuthMiddleware
from app.db.models import APIKey, Base, Policy, RuleSet

CANARY = "CANARY-resp-3d9a-secret"


@pytest.fixture
def client_and_key():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    session = SessionLocal()
    policy = Policy(name="p", type="application", report_only=False, is_default=True)
    session.add(policy)
    session.flush()
    for event_type in ("input", "output"):
        session.add(
            RuleSet(
                policy_id=policy.id,
                event_type=event_type,
                # custom_entity records the matched value and its offset.
                detectors={"custom_entity": {"enabled": True, "action": "redact", "patterns": [CANARY]}},
            )
        )
    raw_key = generate_key(prefix="ak")
    session.add(APIKey(name="k", key_hash=hash_key(raw_key), key_prefix=key_prefix(raw_key), role="admin"))
    session.commit()
    session.close()

    from app.interaction_log import InteractionLog
    from app.services.policy_service import PolicyService
    from app.vault_manager import VaultManager

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = SessionLocal
    app.state.policy_service = PolicyService(session_factory=SessionLocal)
    app.state.vault_manager = VaultManager(session_factory=SessionLocal)
    app.state.interaction_log = InteractionLog(session_factory=SessionLocal)

    class _NoExport:
        async def emit(self, **kwargs):
            return None

    app.state.export_service = _NoExport()

    from app.routes import guard

    app.include_router(guard.router)
    return TestClient(app), raw_key


def test_the_response_does_not_carry_the_matched_value(client_and_key):
    client, key = client_and_key

    resp = client.post(
        "/v1/guard_chat_completions",
        json={
            "guard_input": {"messages": [{"role": "user", "content": f"my token is {CANARY} ok"}]},
            "event_type": "input",
        },
        headers={"Authorization": f"Bearer {key}"},
    )

    assert resp.status_code == 200
    body = json.dumps(resp.json())
    assert CANARY not in body, "the matched value came back in the response"
    assert "start_pos" not in body, "an offset came back in the response"


def test_the_response_still_says_what_fired(client_and_key):
    """Projection must not make the verdict useless."""
    client, key = client_and_key

    resp = client.post(
        "/v1/guard_chat_completions",
        json={
            "guard_input": {"messages": [{"role": "user", "content": f"my token is {CANARY} ok"}]},
            "event_type": "input",
        },
        headers={"Authorization": f"Bearer {key}"},
    )

    detectors = resp.json()["result"]["detectors"]
    assert detectors["custom_entity"]["detected"] is True
    assert detectors["custom_entity"]["entities"] == [{"type": "CUSTOM", "count": 1}]


def test_the_caller_still_gets_the_sanitised_text(client_and_key):
    """guard_output is what the caller acts on, and it must survive."""
    client, key = client_and_key

    resp = client.post(
        "/v1/guard_chat_completions",
        json={
            "guard_input": {"messages": [{"role": "user", "content": f"my token is {CANARY} ok"}]},
            "event_type": "input",
        },
        headers={"Authorization": f"Bearer {key}"},
    )

    result = resp.json()["result"]
    assert result["transformed"] is True
    assert CANARY not in json.dumps(result["guard_output"])


# ---------------------------------------------------------------------------
# Representative payloads, not just the one shape I happened to test
# ---------------------------------------------------------------------------


# Shapes taken from the detectors themselves, not invented. My first version
# used `secrets` (the class name) rather than `secret_and_key_entity` (the
# policy key that actually appears in scan_result.detectors), and gave topic
# and malicious_prompt fields they do not emit — so it proved the projector
# drops an arbitrary object, not that it handles the real contracts.
RAW_SHAPES = {
    "malicious_entity": {
        "detected": True,
        "status": "ok",
        "data": {
            "entities": [
                {
                    "type": "URL",
                    "value": f"hxxps://x.test/{CANARY}",
                    "raw": f"https://x.test/{CANARY}",
                    "action": "defanged",
                    "start_pos": 9,
                }
            ]
        },
    },
    "confidential_and_pii_entity": {
        "detected": True,
        "status": "ok",
        "data": {"entities": [{"type": "US_SSN", "value": CANARY, "action": "redacted:replaced", "start_pos": 4}]},
    },
    "secret_and_key_entity": {
        "detected": True,
        "status": "ok",
        "data": {"entities": [{"type": "API_KEY", "value": CANARY, "action": "redacted:replaced", "start_pos": 0}]},
    },
    "malicious_prompt": {
        "detected": True,
        "status": "ok",
        "data": {"analyzer_responses": [{"analyzer": f"model-{CANARY}", "confidence": 0.99}]},
    },
    "topic": {
        "detected": True,
        "status": "ok",
        "data": {"topics": [{"topic": CANARY, "confidence": 0.8}], "action": "block"},
    },
    "failed_detector": {"detected": False, "status": "failed", "failure_code": "dependency_missing"},
    "skipped_detector": {"detected": False, "status": "skipped", "skip_reason": "short_circuited"},
}



@pytest.mark.parametrize("name", sorted(RAW_SHAPES))
def test_no_representative_payload_leaks_through_projection(name):
    """The route test used custom_entity, whose payload is only one shape."""
    from app.services.safe_export_evidence import project_detectors

    projected = project_detectors({name: RAW_SHAPES[name]})

    body = json.dumps(projected)
    assert CANARY not in body, f"{name} leaked its value"
    assert "start_pos" not in body
    assert "raw" not in body
    assert "analyzer_responses" not in body


def test_a_failed_detector_keeps_its_failure_code():
    """Dropping this was a contract regression, not a privacy gain: it is the
    difference between a missing dependency and a crashed scan."""
    from app.services.safe_export_evidence import project_detectors

    projected = project_detectors({"d": RAW_SHAPES["failed_detector"]})

    assert projected["d"]["status"] == "failed"
    assert projected["d"]["failure_code"] == "dependency_missing"


def test_a_skipped_detector_keeps_its_reason():
    from app.services.safe_export_evidence import project_detectors

    projected = project_detectors({"d": RAW_SHAPES["skipped_detector"]})

    assert projected["d"]["skip_reason"] == "short_circuited"


@pytest.mark.parametrize("field", ["failure_code", "skip_reason", "status"])
def test_an_identifier_shaped_string_is_not_a_valid_code(field):
    """I wrote a comment saying these are fixed enum values, then accepted any
    64-character identifier. 'sk_live_SECRET' is identifier-shaped."""
    from app.services.safe_export_evidence import project_detectors

    projected = project_detectors({"d": {"detected": False, field: "sk_live_SECRET"}})

    assert field not in projected["d"], f"{field} accepted an arbitrary identifier"


@pytest.mark.parametrize(
    "field,value",
    [
        ("failure_code", "dependency_missing"),
        ("skip_reason", "short_circuited"),
        ("status", "failed"),
    ],
)
def test_a_real_enum_value_survives(field, value):
    """Guards against the check being so strict it drops the real thing."""
    from app.services.safe_export_evidence import project_detectors

    projected = project_detectors({"d": {"detected": False, field: value}})

    assert projected["d"][field] == value


def test_the_vocabularies_come_from_the_enums_not_a_restated_list():
    """A code added to the enum must not become silently unexportable."""
    from app.detectors.base import FailureCode
    from app.services.safe_export_evidence import project_detectors

    for code in FailureCode:
        projected = project_detectors({"d": {"detected": False, "failure_code": code.value}})
        assert projected["d"]["failure_code"] == code.value, f"{code.value} would be dropped"
