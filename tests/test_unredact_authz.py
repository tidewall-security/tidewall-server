"""Who may reverse a redaction.

`/v1/unredact` returns the ORIGINAL sensitive text that redaction removed. It
is the highest-value endpoint in the product, and it required only the generic
`api` role — which every enrolled device holds — while resolving a
caller-supplied vault id with no ownership check at all. `Vault` has no owner
column, so there is nothing to check against yet.

A device credential is issued to a browser extension on someone's laptop. It
should be able to ask whether a prompt is allowed. It should not be able to ask
what a redaction concealed, least of all for a vault it never created.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.auth.middleware import AuthMiddleware
from app.db.models import AccessToken, APIKey, Base, Device, Policy


@pytest.fixture
def env():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = Session

    class _Vaults:
        def get_vault(self, _vault_id):
            return None

    app.state.vault_manager = _Vaults()

    from app.routes import unredact

    app.include_router(unredact.router)

    session = Session()
    session.add(Policy(id="policy-a", name="policy-a", type="application"))
    session.commit()
    session.close()
    return TestClient(app), Session


def _device_token(Session, *, status="active"):
    raw = generate_key(prefix="at")
    session = Session()
    device = Device(
        installation_id=f"00000000-0000-4000-8000-{raw[-12:]}",
        device_name="laptop",
        user_name="someone",
        user_email="someone@example.com",
        status=status,
        policy_id="policy-a",
    )
    session.add(device)
    session.flush()
    session.add(
        AccessToken(
            token_hash=hash_key(raw),
            device_id=device.id,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    session.commit()
    session.close()
    return {"Authorization": f"Bearer {raw}"}


def _api_key(Session):
    raw = generate_key(prefix="ak")
    session = Session()
    session.add(
        APIKey(
            name="integration",
            key_hash=hash_key(raw),
            key_prefix=key_prefix(raw),
            role="api",
            policy_id="policy-a",
        )
    )
    session.commit()
    session.close()
    return {"Authorization": f"Bearer {raw}"}


def _ctx(vault_id="someone-elses-vault"):
    return base64.b64encode(json.dumps({"vault_id": vault_id}).encode()).decode()


def test_a_DEVICE_token_cannot_reverse_a_redaction(env):
    client, Session = env
    resp = client.post(
        "/v1/unredact",
        headers=_device_token(Session),
        json={"fpe_context": _ctx(), "redacted_data": "tok_1"},
    )
    assert resp.status_code == 403, resp.text


def test_it_is_denied_on_CREDENTIAL_TYPE_not_on_the_vault_being_missing(env):
    # The vault manager returns None for everything here, so a route that
    # denied late would 404 or 400. Denial must happen before any lookup:
    # otherwise the endpoint is an existence oracle for vault ids.
    client, Session = env
    resp = client.post(
        "/v1/unredact",
        headers=_device_token(Session),
        json={"fpe_context": _ctx("definitely-not-a-real-vault"), "redacted_data": "tok_1"},
    )
    assert resp.status_code == 403, resp.text
    assert "vault" not in resp.text.lower()


def test_an_API_KEY_integration_is_NOT_denied(env):
    # The denial is about device credentials, not about the `api` role — a
    # server-to-server integration still has a legitimate reason to unredact.
    client, Session = env
    resp = client.post(
        "/v1/unredact",
        headers=_api_key(Session),
        json={"fpe_context": _ctx(), "redacted_data": "tok_1"},
    )
    assert resp.status_code != 403, resp.text


def test_an_unauthenticated_caller_is_still_rejected(env):
    client, _ = env
    resp = client.post("/v1/unredact", json={"fpe_context": _ctx(), "redacted_data": "tok_1"})
    assert resp.status_code in (401, 403)
