"""Integration tests for the guard evaluation endpoint POST /v1/guard_chat_completions."""

from __future__ import annotations

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

    from app.routes import guard, registration

    app.include_router(guard.router)
    app.include_router(registration.router)

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
        json={"name": "test-rt", "policy_id": policy_id},
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
