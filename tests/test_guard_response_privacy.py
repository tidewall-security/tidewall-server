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
