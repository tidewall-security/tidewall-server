"""An unredact that recovers nothing must not report success.

`VaultManager.create_vault` persists the vault while it is still empty, and
nothing writes it back after the PII detector populates it -- `to_bytes()` has
one production call site. Every stored row is therefore
`{"placeholders": {}, "counters": {}}`.

On a cache miss the route loaded that empty vault, called `unredact()` -- which
replaced nothing -- and returned the REDACTED text with `status="Success"` and
`summary="Unredacted via vault"`. Across workers the miss is the common case,
so the caller was routinely told a reversal had happened and handed back the
text it sent.

A vault id only exists because a redaction produced one, so an empty vault means
the mapping was lost. Saying "Success" to that is a lie about data.
"""

from __future__ import annotations

import base64
import json

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.auth.middleware import AuthMiddleware
from app.db.models import APIKey, Base, Policy
from app.vault import TidewallVault


def _ctx(vault_id: str = "vault-1") -> str:
    return base64.b64encode(json.dumps({"vault_id": vault_id}).encode()).decode()


def _app(vault: TidewallVault | None):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = Session

    class _Vaults:
        def get_vault(self, _vault_id):
            return vault

    app.state.vault_manager = _Vaults()

    from app.routes import unredact

    app.include_router(unredact.router)

    raw = generate_key(prefix="ak")
    session = Session()
    session.add(Policy(id="policy-a", name="policy-a", type="application"))
    session.add(APIKey(name="api", key_hash=hash_key(raw), key_prefix=key_prefix(raw), role="api"))
    session.commit()
    session.close()
    return TestClient(app), raw


def _post(client, key, data="[REDACTED_EMAIL_1]"):
    return client.post(
        "/v1/unredact",
        headers={"Authorization": f"Bearer {key}"},
        json={"fpe_context": _ctx(), "redacted_data": data},
    )


def test_an_empty_vault_is_not_reported_as_a_successful_unredact():
    client, key = _app(TidewallVault())

    resp = _post(client, key)

    assert resp.status_code != 200, "an unredact that recovered nothing reported success"


def test_an_empty_vault_does_not_return_the_redacted_text_as_the_original():
    """The specific harm: the caller is handed back what it sent."""
    client, key = _app(TidewallVault())

    resp = _post(client, key, data="[REDACTED_EMAIL_1]")

    body = resp.json()
    assert body.get("result", {}).get("data") != "[REDACTED_EMAIL_1]"


def test_a_populated_vault_still_unredacts():
    """The positive control.

    Without this the guard above passes just as well if unredact is broken for
    every input, which would be a worse cure than the disease.
    """
    vault = TidewallVault()
    placeholder = vault.store("EMAIL", "jon@example.com")
    client, key = _app(vault)

    resp = _post(client, key, data=f"contact {placeholder}")

    assert resp.status_code == 200
    assert resp.json()["result"]["data"] == "contact jon@example.com"


def test_a_missing_vault_is_still_a_404():
    """Unchanged: absent and empty are different failures."""
    client, key = _app(None)

    assert _post(client, key).status_code == 404
