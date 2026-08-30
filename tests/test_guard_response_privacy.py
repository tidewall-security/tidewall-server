"""The guard response must not carry exact matched values.

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
    "code": {"detected": False, "status": "failed", "failure_code": "dependency_missing"},
    "language": {"detected": False, "status": "skipped", "skip_reason": "short_circuited"},
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

    projected = project_detectors({"code": RAW_SHAPES["code"]})

    assert projected["code"]["status"] == "failed"
    assert projected["code"]["failure_code"] == "dependency_missing"


def test_a_skipped_detector_keeps_its_reason():
    from app.services.safe_export_evidence import project_detectors

    projected = project_detectors({"language": RAW_SHAPES["language"]})

    assert projected["language"]["skip_reason"] == "short_circuited"


@pytest.mark.parametrize("field", ["failure_code", "skip_reason", "status"])
def test_an_identifier_shaped_string_is_not_a_valid_code(field):
    """I wrote a comment saying these are fixed enum values, then accepted any
    64-character identifier. 'sk_live_SECRET' is identifier-shaped."""
    from app.services.safe_export_evidence import project_detectors

    projected = project_detectors({"code": {"detected": False, field: "sk_live_SECRET"}})

    assert field not in projected["code"], f"{field} accepted an arbitrary identifier"


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

    projected = project_detectors({"code": {"detected": False, field: value}})

    assert projected["code"][field] == value


def test_the_vocabularies_come_from_the_enums_not_a_restated_list():
    """A code added to the enum must not become silently unexportable."""
    from app.detectors.base import FailureCode
    from app.services.safe_export_evidence import project_detectors

    for code in FailureCode:
        projected = project_detectors({"code": {"detected": False, "failure_code": code.value}})
        assert projected["code"]["failure_code"] == code.value, f"{code.value} would be dropped"


def test_exact_matches_are_captured_when_capture_is_on(client_and_key):
    """The middle role tier needs matched values, and they must be provenance —
    validated against the text the detector was given — not values copied out
    of a public payload."""
    from app.db.models import InteractionContent, Policy

    client, key = client_and_key
    factory = client.app.state.session_factory

    session = factory()
    try:
        policy = session.query(Policy).first()
        policy.raw_content_enabled = True
        session.commit()
    finally:
        session.close()

    client.app.state.policy_service.invalidate_all_engines()

    resp = client.post(
        "/v1/guard_chat_completions",
        json={
            "guard_input": {"messages": [{"role": "user", "content": f"token {CANARY} here"}]},
            "event_type": "input",
        },
        headers={"Authorization": f"Bearer {key}"},
    )
    assert resp.status_code == 200

    session = factory()
    try:
        content = session.query(InteractionContent).one()
    finally:
        session.close()

    assert content.matches_json is not None, "no exact matches were captured"
    stored = json.dumps(content.matches_json)
    assert CANARY in stored, "the matched value was not recorded"
    assert "start" not in stored and "end" not in stored, "offsets reached storage"


def test_no_matches_are_captured_when_capture_is_off(client_and_key):
    from app.db.models import InteractionContent

    client, key = client_and_key

    client.post(
        "/v1/guard_chat_completions",
        json={
            "guard_input": {"messages": [{"role": "user", "content": f"token {CANARY} here"}]},
            "event_type": "input",
        },
        headers={"Authorization": f"Bearer {key}"},
    )

    session = client.app.state.session_factory()
    try:
        assert session.query(InteractionContent).count() == 0
    finally:
        session.close()


def test_a_match_in_a_later_message_is_attributed_to_that_message(client_and_key):
    """The guard flattens messages before scanning, so a detector reports
    offsets into the concatenation. Recording those as message[0] was factually
    wrong: a match in the third message was stored as having come from the
    first, and the role was always lost."""
    from app.db.models import InteractionContent, Policy

    client, key = client_and_key
    factory = client.app.state.session_factory

    session = factory()
    try:
        session.query(Policy).first().raw_content_enabled = True
        session.commit()
    finally:
        session.close()
    client.app.state.policy_service.invalidate_all_engines()

    client.post(
        "/v1/guard_chat_completions",
        json={
            "guard_input": {
                "messages": [
                    {"role": "system", "content": "you are helpful"},
                    {"role": "user", "content": "nothing here"},
                    {"role": "assistant", "content": f"the token is {CANARY}"},
                ]
            },
            "event_type": "input",
        },
        headers={"Authorization": f"Bearer {key}"},
    )

    session = factory()
    try:
        matches = session.query(InteractionContent).one().matches_json
    finally:
        session.close()

    assert matches and matches["matches"], "no match was captured"
    entry = next(m for m in matches["matches"] if CANARY in m["value"])
    assert entry["source"]["index"] == 2, f"attributed to message {entry['source']['index']}, not 2"
    assert entry["source"]["role"] == "assistant"


def test_a_match_spanning_the_join_boundary_is_dropped(client_and_key):
    """The separator can create a string that occurs in no original message.
    Attributing it to whichever message it started in would be a fabricated
    provenance record."""
    from app.services.audit_evidence import MatchCollector, SourceRef

    collector = MatchCollector()
    collector.register_flattened(
        [
            (SourceRef(kind="message", index=0, field="content", role="user"), "abc", 0),
            (SourceRef(kind="message", index=1, field="content", role="user"), "def", 4),
        ]
    )

    # "c d" spans the join.
    assert collector.resolve_flattened(2, 5) is None
    # Wholly inside the second message.
    resolved = collector.resolve_flattened(4, 7)
    assert resolved is not None and resolved[0].index == 1


def _post(client, key, messages):
    return client.post(
        "/v1/guard_chat_completions",
        json={"guard_input": {"messages": messages}, "event_type": "input"},
        headers={"Authorization": f"Bearer {key}"},
    )


def test_capture_does_not_change_the_security_decision(client_and_key):
    """The governing rule.

    Reporting a match used to raise into detector execution, and the engine
    turned that into SCAN_FAILED — so enabling capture could skip a redaction
    that would otherwise have happened. Optional audit must never alter what
    the guard does.
    """
    from app.db.models import Policy

    client, key = client_and_key
    messages = [
        {"role": "user", "content": f"first {CANARY} here"},
        {"role": "assistant", "content": f"second {CANARY} there"},
    ]

    off = _post(client, key, messages).json()["result"]

    session = client.app.state.session_factory()
    try:
        session.query(Policy).first().raw_content_enabled = True
        session.commit()
    finally:
        session.close()
    client.app.state.policy_service.invalidate_all_engines()

    on = _post(client, key, messages).json()["result"]

    assert on["blocked"] == off["blocked"]
    assert on["transformed"] == off["transformed"]
    assert on["guard_output"] == off["guard_output"], "capture changed the sanitised output"
    assert on["detectors"] == off["detectors"], "capture changed the detector verdicts"


@pytest.mark.parametrize("role", ["human/operator", "rôle", "x" * 200, "tool-call"])
def test_an_unusual_role_is_accepted_whether_or_not_capture_is_on(client_and_key, role):
    """Roles are caller data, not internal discriminators. Feeding one into the
    identifier rule made capture-on reject requests capture-off accepts —
    capture changing what the API accepts."""
    from app.db.models import Policy

    client, key = client_and_key

    session = client.app.state.session_factory()
    try:
        session.query(Policy).first().raw_content_enabled = True
        session.commit()
    finally:
        session.close()
    client.app.state.policy_service.invalidate_all_engines()

    resp = _post(client, key, [{"role": role, "content": "hello"}])

    assert resp.status_code == 200, f"role {role!r} failed the request when capture was on"
