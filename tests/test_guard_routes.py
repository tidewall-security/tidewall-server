"""Integration tests for the guard evaluation endpoint POST /v1/guard_chat_completions."""

from __future__ import annotations

import builtins
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.auth.middleware import AuthMiddleware
from app.db.models import APIKey, Base, Interaction, Policy, RuleSet
from app.interaction_log import InteractionLog
from app.services.export_service import ExportService
from app.services.policy_service import PolicyService
from app.vault_manager import VaultManager


def _make_app_and_client():
    """Create an in-memory SQLite app wired for the guard endpoint."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    # Seed a minimal policy with NO detectors enabled (avoids ML model loading)
    session = SessionLocal()
    policy = Policy(
        name="test_policy",
        type="application",
        description="Test policy with no detectors",
        report_only=False,
        is_default=True,
    )
    session.add(policy)
    session.flush()
    # Captured now: a later commit expires the instance, and reading .id off a
    # detached one raises.
    seeded_policy_id = policy.id

    for event_type in ("input", "output"):
        rs = RuleSet(
            policy_id=policy.id,
            event_type=event_type,
            detectors={},
        )
        session.add(rs)

    session.commit()
    session.close()

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = SessionLocal
    app.state.policy_service = PolicyService(session_factory=SessionLocal)
    app.state.vault_manager = VaultManager(session_factory=SessionLocal)
    app.state.interaction_log = InteractionLog(session_factory=SessionLocal)
    app.state.export_service = ExportService(session_factory=SessionLocal)

    from app.routes import devices, guard, registration

    app.include_router(guard.router)
    app.include_router(registration.router)
    app.include_router(devices.router)

    # Create an admin API key (admin can call guard because admin > api)
    raw_admin_key = generate_key(prefix="ak")
    session = SessionLocal()
    admin_key = APIKey(
        name="test-admin",
        key_hash=hash_key(raw_admin_key),
        key_prefix=key_prefix(raw_admin_key),
        role="admin",
    )
    session.add(admin_key)

    # Create an API-role key (the normal role for guard callers)
    raw_api_key = generate_key(prefix="ak")
    api_key = APIKey(
        name="test-api",
        key_hash=hash_key(raw_api_key),
        key_prefix=key_prefix(raw_api_key),
        role="api",
        # Bound, as a collector key is in a real deployment. Ownership of a
        # vault comes from this binding, and an unbound key deliberately gets
        # no vault and can reverse nothing.
        policy_id=seeded_policy_id,
    )
    session.add(api_key)

    # Create a viewer-role key
    raw_viewer_key = generate_key(prefix="ak")
    viewer_key = APIKey(
        name="test-viewer",
        key_hash=hash_key(raw_viewer_key),
        key_prefix=key_prefix(raw_viewer_key),
        role="viewer",
    )
    session.add(viewer_key)

    session.commit()
    session.close()

    client = TestClient(app)
    return client, raw_admin_key, raw_api_key, raw_viewer_key, SessionLocal


@pytest.fixture
def setup():
    client, admin_key, api_key, viewer_key, session_factory = _make_app_and_client()
    return client, admin_key, api_key, viewer_key, session_factory


def _guard_payload(messages=None, event_type="input", **kwargs):
    """Build a minimal guard request body."""
    if messages is None:
        messages = [{"role": "user", "content": "Hello, how are you?"}]
    body = {
        "guard_input": {"messages": messages},
        "event_type": event_type,
    }
    body.update(kwargs)
    return body


# ------------------------------------------------------------------
# 1. Basic allowed request
# ------------------------------------------------------------------


def test_basic_allowed_request(setup):
    """Clean text with no detectors should return status=allowed, blocked=false."""
    client, _, api_key, _, _ = setup
    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(),
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "Success"
    assert data["result"]["blocked"] is False
    assert data["result"]["transformed"] is False


def test_admin_can_also_call_guard(setup):
    """Admin role is higher than api, so admin should also be able to call guard."""
    client, admin_key, _, _, _ = setup
    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(),
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    assert resp.json()["result"]["blocked"] is False


# ------------------------------------------------------------------
# 2. Missing/empty messages
# ------------------------------------------------------------------


def test_empty_messages_list(setup):
    """An empty messages list should still return a valid response."""
    client, _, api_key, _, _ = setup
    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(messages=[]),
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "Success"
    assert data["result"]["blocked"] is False


def test_missing_guard_input_returns_422(setup):
    """Request without guard_input should be rejected by Pydantic validation."""
    client, _, api_key, _, _ = setup
    resp = client.post(
        "/v1/guard_chat_completions",
        json={"event_type": "input"},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 422


# ------------------------------------------------------------------
# 3. Auth required (no token -> 401)
# ------------------------------------------------------------------


def test_no_auth_returns_401(setup):
    """Request without Authorization header should be rejected."""
    client, _, _, _, _ = setup
    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(),
    )
    assert resp.status_code == 401


def test_invalid_token_returns_401(setup):
    """Request with a bogus token should be rejected."""
    client, _, _, _, _ = setup
    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(),
        headers={"Authorization": "Bearer ak_bogus_invalid_key"},
    )
    assert resp.status_code == 401


# ------------------------------------------------------------------
# 4. Role enforcement
# ------------------------------------------------------------------


def test_viewer_can_call_guard(setup):
    """Viewer role (level 2) is above api (level 1) in the hierarchy, so viewer is permitted."""
    client, _, _, viewer_key, _ = setup
    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(),
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 200


def test_rt_token_cannot_call_guard(setup):
    """Registration tokens (role=rt, level 0) cannot access the guard endpoint."""
    client, admin_key, _, _, session_factory = setup

    # A registration token must now name the policy its devices will inherit.
    session = session_factory()
    try:
        policy_id = session.query(Policy).filter_by(is_default=True).one().id
    finally:
        session.close()

    # Create an rt_ token via the registration endpoint
    resp = client.post(
        "/v1/registration-tokens",
        json={
            "name": "test-rt",
            "policy_id": policy_id,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 201
    rt_token = resp.json()["token"]

    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(),
        headers={"Authorization": f"Bearer {rt_token}"},
    )
    assert resp.status_code == 403


# ------------------------------------------------------------------
# 5. Request with event_type="output"
# ------------------------------------------------------------------


def test_output_event_type(setup):
    """event_type=output should use the output rule set and succeed."""
    client, _, api_key, _, _ = setup
    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(
            messages=[{"role": "assistant", "content": "Here is the answer."}],
            event_type="output",
        ),
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "Success"
    assert data["result"]["blocked"] is False


# ------------------------------------------------------------------
# 6. Response shape validation
# ------------------------------------------------------------------


def test_response_shape(setup):
    """Verify the response has all required top-level and result fields."""
    client, _, api_key, _, _ = setup
    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(),
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    # Top-level fields
    assert "request_id" in data
    assert data["request_id"].startswith("tw_")
    assert "request_time" in data
    assert "response_time" in data
    assert "status" in data
    assert "summary" in data

    # Result fields
    result = data["result"]
    assert "blocked" in result
    assert "transformed" in result
    assert "policy" in result
    assert result["policy"] == "test_policy"
    assert "detectors" in result
    assert isinstance(result["detectors"], dict)
    assert "access_rules" in result
    assert isinstance(result["access_rules"], dict)


# ------------------------------------------------------------------
# 7. Interaction gets logged (check DB after request)
# ------------------------------------------------------------------


def test_interaction_logged(setup):
    """After a guard request, an Interaction row should exist in the DB."""
    client, _, api_key, _, session_factory = setup

    # Verify no interactions exist yet
    session = session_factory()
    count_before = session.query(Interaction).count()
    session.close()

    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(
            messages=[{"role": "user", "content": "Log this interaction."}],
            app_id="test-app",
            user_id="test-user",
            model="gpt-4",
            llm_provider="openai",
        ),
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 200
    request_id = resp.json()["request_id"]

    session = session_factory()
    count_after = session.query(Interaction).count()
    assert count_after == count_before + 1

    interaction = session.query(Interaction).filter_by(request_id=request_id).first()
    assert interaction is not None
    assert interaction.event_type == "input"
    assert interaction.policy_name == "test_policy"
    assert interaction.blocked is False
    assert interaction.app_id == "test-app"
    assert interaction.user_id == "test-user"
    assert interaction.model == "gpt-4"
    assert interaction.status == "allowed"
    session.close()


def test_multiple_interactions_logged(setup):
    """Multiple guard requests should each create a separate interaction row."""
    client, _, api_key, _, session_factory = setup

    for i in range(3):
        resp = client.post(
            "/v1/guard_chat_completions",
            json=_guard_payload(messages=[{"role": "user", "content": f"Message {i}"}]),
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200

    session = session_factory()
    count = session.query(Interaction).count()
    assert count == 3
    session.close()


CAPTURE_CANARY = "swordfish-42"


def _configure(session_factory, *, capture: bool):
    """Enable capture and a redacting regex detector, so the parity comparison
    is made against a request that actually gets enforced on."""
    session = session_factory()
    policy = session.query(Policy).filter_by(name="test_policy").first()
    policy.raw_content_enabled = capture
    for rs in session.query(RuleSet).filter_by(policy_id=policy.id):
        rs.detectors = {"custom_entity": {"enabled": True, "action": "redact", "patterns": [CAPTURE_CANARY]}}
    session.commit()
    session.close()


def _enforcement(response):
    """The parts of the response that are the security decision.

    GuardResponse sets extra="allow", so a typo'd field name silently reads
    None and compares equal to another None. Assert the shape first.
    """
    body = response.json()
    for field in ("status", "summary", "result"):
        assert field in body, f"{field!r} missing from the guard response"
    result = dict(body["result"])
    for field in ("blocked", "transformed", "detectors", "guard_output"):
        assert field in result, f"result.{field!r} missing from the guard response"
    # A fresh vault token per request. Excluded deliberately: comparing it
    # would be comparing nonces.
    #
    # Its presence used to be asserted here, as the proof that a capture
    # failure had not suppressed redaction entirely. It cannot be any more, and
    # should never have been: the redactor these tests configure is
    # custom_entity, which replaces the match without recording the original
    # anywhere, so the vault is empty and there is nothing to reverse. The
    # token was issued regardless, and /v1/unredact would have refused it.
    # `transformed` is the same proof and is the thing actually being claimed.
    result.pop("fpe_context", None)
    assert result["transformed"] is True, "nothing was redacted, so this compares two clean scans"
    return {
        "status": body["status"],
        "summary": body["summary"],
        "result": result,
    }


def _stored(session_factory):
    session = session_factory()
    try:
        row = session.query(Interaction).order_by(Interaction.id.desc()).first()
        return (row.blocked, row.transformed, row.status)
    finally:
        session.close()


def test_capture_setup_failure_does_not_change_the_enforcement_response(setup, monkeypatch):
    """Optional audit capture must never decide what the guard does.

    Collector construction and source registration happen in the route, before
    the scan. Unwrapped, an exception there returned HTTP 500 for a request
    that capture-off would have scanned, enforced on, and answered normally.
    """
    client, _admin_key, api_key, _viewer_key, session_factory = setup
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = _guard_payload(
        messages=[
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": f"my code is {CAPTURE_CANARY} ok"},
        ]
    )

    # Baseline: capture off, detector on. This redacts, so there is a real
    # enforcement outcome to compare rather than an empty one.
    _configure(session_factory, capture=False)
    off = client.post("/v1/guard_chat_completions", json=payload, headers=headers)
    assert off.status_code == 200
    baseline = _enforcement(off)
    assert baseline["result"]["transformed"] is True, "the detector did not fire, so parity proves nothing"
    stored_off = _stored(session_factory)

    # Capture on, but every attempt to set it up fails.
    _configure(session_factory, capture=True)
    import app.services.audit_evidence as audit_evidence

    def _explode(*args, **kwargs):
        raise RuntimeError("collector unavailable")

    monkeypatch.setattr(audit_evidence, "MatchCollector", _explode)
    on = client.post("/v1/guard_chat_completions", json=payload, headers=headers)

    assert on.status_code == 200
    assert _enforcement(on) == baseline, "capture setup failure changed the enforcement response"
    assert _stored(session_factory) == stored_off, "capture setup failure changed the stored verdict"


def test_registration_failure_also_falls_back_to_capture_off_scanning(setup, monkeypatch):
    """The same for the second half of setup: registering the sources."""
    client, _admin_key, api_key, _viewer_key, session_factory = setup
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = _guard_payload(messages=[{"role": "user", "content": f"my code is {CAPTURE_CANARY} ok"}])

    _configure(session_factory, capture=False)
    off = client.post("/v1/guard_chat_completions", json=payload, headers=headers)
    baseline = _enforcement(off)
    assert baseline["result"]["transformed"] is True

    _configure(session_factory, capture=True)
    import app.services.audit_evidence as audit_evidence

    def _explode(self, segments):
        raise RuntimeError("registration failed")

    monkeypatch.setattr(audit_evidence.MatchCollector, "register_flattened", _explode)
    on = client.post("/v1/guard_chat_completions", json=payload, headers=headers)

    assert on.status_code == 200
    assert _enforcement(on) == baseline


def test_a_capture_dependency_failure_still_commits_the_verdict(setup, monkeypatch):
    """Loading the capture module is capture-only work too.

    The import sat outside the failure boundary, so an ImportError escaped the
    writer, escaped the route's awaited thread, and lost both the response and
    the audit event that capture-off would have stored.
    """
    client, _admin_key, api_key, _viewer_key, session_factory = setup
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = _guard_payload(messages=[{"role": "user", "content": f"my code is {CAPTURE_CANARY} ok"}])

    _configure(session_factory, capture=False)
    off = client.post("/v1/guard_chat_completions", json=payload, headers=headers)
    baseline = _enforcement(off)

    _configure(session_factory, capture=True)
    real_import = builtins.__import__

    def _fail_capture_import(name, *args, **kwargs):
        if name == "app.services.content_capture":
            raise ImportError("capture module unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fail_capture_import)
    on = client.post("/v1/guard_chat_completions", json=payload, headers=headers)
    monkeypatch.undo()

    assert on.status_code == 200, "a capture dependency failure became an HTTP error"
    assert _enforcement(on) == baseline
    session = session_factory()
    try:
        row = session.query(Interaction).order_by(Interaction.id.desc()).first()
        assert row is not None, "the audit event was lost to a capture-only failure"
        assert row.content_available is False
    finally:
        session.close()


def test_a_capture_failure_that_cannot_even_be_logged_still_does_not_change_enforcement(setup, monkeypatch):
    """The boundary has to include its own failure reporting.

    Each capture-only operation is wrapped, but the report inside the handler
    was not. A logging Filter raises straight through Logger.handle — unlike a
    handler's emit(), which the logging module catches — so an operator's
    broken filter could turn a contained capture failure back into a 500.
    """
    import logging

    client, _admin_key, api_key, _viewer_key, session_factory = setup
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = _guard_payload(messages=[{"role": "user", "content": f"my code is {CAPTURE_CANARY} ok"}])

    _configure(session_factory, capture=False)
    baseline = _enforcement(client.post("/v1/guard_chat_completions", json=payload, headers=headers))

    _configure(session_factory, capture=True)
    import app.services.audit_evidence as audit_evidence

    def _explode(*args, **kwargs):
        raise RuntimeError("collector unavailable")

    class _HostileFilter(logging.Filter):
        def filter(self, record):
            raise RuntimeError("filter is broken")

    monkeypatch.setattr(audit_evidence, "MatchCollector", _explode)
    hostile = _HostileFilter()
    guard_logger = logging.getLogger("app.routes.guard")
    guard_logger.addFilter(hostile)
    try:
        on = client.post("/v1/guard_chat_completions", json=payload, headers=headers)
    finally:
        guard_logger.removeFilter(hostile)

    assert on.status_code == 200, "a capture failure that could not be logged became an HTTP error"
    assert _enforcement(on) == baseline


# ------------------------------------------------------------------
# A pending device holds credentials and reaches nothing
# ------------------------------------------------------------------


def _enrol_via_http(client, admin_key, session_factory, *, pre_authorized: bool, label: str):
    session = session_factory()
    try:
        policy_id = session.query(Policy).filter_by(is_default=True).one().id
    finally:
        session.close()

    rt = client.post(
        "/v1/registration-tokens",
        json={
            "name": f"rt-{label}",
            "policy_id": policy_id,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            "pre_authorized": pre_authorized,
        },
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert rt.status_code == 201, rt.text

    enrolled = client.post(
        "/v1/devices/enrol",
        json={
            "installation_id": str(uuid.uuid5(uuid.NAMESPACE_DNS, label)),
            "device_name": "d",
            "user_name": "u",
            "user_email": "u@example.com",
            "browser": "b",
            "os": "o",
            "extension_version": "1",
        },
        headers={"Authorization": f"Bearer {rt.json()['token']}"},
    )
    assert enrolled.status_code == 201, enrolled.text
    return enrolled.json()["result"]


def test_a_pending_device_cannot_call_guard(setup):
    """The control is the device's status, not the absence of a credential.

    Asserted against the real guard endpoint rather than a column. A test that
    read `device.status == "pending"` would still pass if the middleware
    stopped consulting status altogether, which is the failure that matters.
    """
    client, admin_key, _api_key, _viewer_key, session_factory = setup
    enrolled = _enrol_via_http(client, admin_key, session_factory, pre_authorized=False, label="pending-guard")

    assert enrolled["device_status"] == "pending"

    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(),
        headers={"Authorization": f"Bearer {enrolled['access_token']['token']}"},
    )

    assert resp.status_code == 401, "a pending device reached the guard"


def test_an_approved_device_can_call_guard(setup):
    """The positive control.

    Without this, the test above passes just as well if enrolment is broken and
    the token is worthless for every reason. This proves the same credential
    works once the device is approved, so the pending refusal is the status
    doing it.
    """
    client, admin_key, _api_key, _viewer_key, session_factory = setup
    enrolled = _enrol_via_http(client, admin_key, session_factory, pre_authorized=False, label="approved-guard")
    token = enrolled["access_token"]["token"]

    approve = client.post(
        f"/v1/devices/{enrolled['device_id']}/approve",
        json={"confirmation_code": enrolled["confirmation_code"]},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert approve.status_code == 200, approve.text

    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 200, resp.text


def test_a_pre_authorized_device_can_call_guard_without_approval(setup):
    """The fleet path: no admin step, by deliberate configuration."""
    client, admin_key, _api_key, _viewer_key, session_factory = setup
    enrolled = _enrol_via_http(client, admin_key, session_factory, pre_authorized=True, label="fleet-guard")

    assert enrolled["device_status"] == "active"

    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(),
        headers={"Authorization": f"Bearer {enrolled['access_token']['token']}"},
    )

    assert resp.status_code == 200, resp.text


def test_a_refresh_token_cannot_call_guard(setup):
    """The credential with the longest life must have the smallest reach."""
    client, admin_key, _api_key, _viewer_key, session_factory = setup
    enrolled = _enrol_via_http(client, admin_key, session_factory, pre_authorized=True, label="dr-guard")

    resp = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(),
        headers={"Authorization": f"Bearer {enrolled['refresh_token']['token']}"},
    )

    assert resp.status_code == 403

    # Positive control: the ACCESS token from the same enrolment does work, so
    # the refusal is the credential type and not a broken fixture.
    ok = client.post(
        "/v1/guard_chat_completions",
        json=_guard_payload(),
        headers={"Authorization": f"Bearer {enrolled['access_token']['token']}"},
    )
    assert ok.status_code == 200


def test_missing_rule_set_refuses_rather_than_silently_using_the_input_engine():
    """A missing rule set is control-plane uncertainty, so the request fails.

    This previously fell back to the `input` engine. Because no creation path
    made rule sets for the tool event types, that fallback ran for every
    tool_input, tool_output and tool_listing request ever served -- scanning
    them under the input policy while appearing to have none of their own.

    All three creation paths now produce a rule set per event type and a
    migration backfills existing databases, so a missing row means genuine
    misconfiguration. The codebase's stance on control uncertainty is to fail
    rather than proceed under a different configuration, matching the missing
    default policy a few lines above.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.auth.key_utils import generate_key, hash_key, key_prefix
    from app.auth.middleware import AuthMiddleware
    from app.db.models import APIKey, Base, Policy, RuleSet
    from app.interaction_log import InteractionLog
    from app.routes import guard as guard_route
    from app.services.policy_service import PolicyService
    from app.vault_manager import VaultManager

    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    SL = sessionmaker(bind=eng)
    s = SL()
    policy = Policy(name="p", type="application", report_only=False, is_default=True)
    s.add(policy)
    s.flush()
    # Every event type EXCEPT tool_output, which is the missing-row case.
    for et in ("input", "output", "tool_input", "tool_listing"):
        s.add(RuleSet(policy_id=policy.id, event_type=et, detectors={}))
    raw = generate_key(prefix="ak")
    s.add(
        APIKey(
            name="k",
            key_hash=hash_key(raw),
            key_prefix=key_prefix(raw),
            role="admin",
            policy_id=policy.id,
        )
    )
    s.commit()
    policy_id = policy.id  # read before the session closes; the instance detaches
    s.close()

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = SL
    app.state.policy_service = PolicyService(session_factory=SL)
    app.state.vault_manager = VaultManager(session_factory=SL)
    app.state.interaction_log = InteractionLog(session_factory=SL)

    class _NoExport:
        async def emit(self, **kwargs):
            return None

    app.state.export_service = _NoExport()
    app.include_router(guard_route.router)

    resp = TestClient(app, raise_server_exceptions=False).post(
        "/v1/guard_chat_completions",
        json={"guard_input": {"messages": [{"role": "user", "content": "hi"}]}, "event_type": "tool_output"},
        headers={"Authorization": f"Bearer {raw}"},
    )

    assert resp.status_code == 500, "a missing rule set must not be served under another surface"
    detail = resp.json().get("detail", "")
    # HTTPException detail is returned verbatim -- validation_errors.py only
    # sanitises RequestValidationError -- so it must not name internal state.
    assert policy_id not in detail, "the error must not disclose the policy id"
    assert "engine" not in detail.lower(), "the error must not disclose engine internals"


def test_a_rule_set_deleted_after_its_engine_was_cached_refuses():
    """The engine cache can outlive the row it was built from.

    `get_engine` refuses a missing rule set, but it caches on the way through,
    so a later request answers from the cache without consulting the row again.
    The route then looked the rule set up a second time and treated absence as
    "this surface configures no access rules" -- so the request was evaluated
    with none, silently, rather than refused.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.auth.key_utils import generate_key, hash_key, key_prefix
    from app.auth.middleware import AuthMiddleware
    from app.db.models import APIKey, Base, Policy, RuleSet
    from app.interaction_log import InteractionLog
    from app.routes import guard as guard_route
    from app.services.policy_service import PolicyService
    from app.vault_manager import VaultManager

    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    SL = sessionmaker(bind=eng)
    s = SL()
    policy = Policy(name="p", type="application", report_only=False, is_default=True)
    s.add(policy)
    s.flush()
    for et in ("input", "output", "tool_input", "tool_output", "tool_listing"):
        s.add(RuleSet(policy_id=policy.id, event_type=et, detectors={}))
    raw = generate_key(prefix="ak")
    s.add(
        APIKey(
            name="k",
            key_hash=hash_key(raw),
            key_prefix=key_prefix(raw),
            role="admin",
            policy_id=policy.id,
        )
    )
    s.commit()
    policy_id = policy.id
    s.close()

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = SL
    app.state.policy_service = PolicyService(session_factory=SL)
    app.state.vault_manager = VaultManager(session_factory=SL)
    app.state.interaction_log = InteractionLog(session_factory=SL)

    class _NoExport:
        async def emit(self, **kwargs):
            return None

    app.state.export_service = _NoExport()
    app.include_router(guard_route.router)
    client = TestClient(app, raise_server_exceptions=False)
    body = {"guard_input": {"messages": [{"role": "user", "content": "hi"}]}, "event_type": "input"}
    headers = {"Authorization": f"Bearer {raw}"}

    first = client.post("/v1/guard_chat_completions", json=body, headers=headers)
    assert first.status_code == 200, "the engine must build and cache before the row is removed"

    s2 = SL()
    s2.query(RuleSet).filter_by(policy_id=policy_id, event_type="input").delete()
    s2.commit()
    s2.close()

    second = client.post("/v1/guard_chat_completions", json=body, headers=headers)
    assert second.status_code == 500, "a vanished rule set must refuse, not evaluate with no access rules"
    assert policy_id not in second.json().get("detail", "")
