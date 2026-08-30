"""Recording that someone tried to reverse a redaction.

`/v1/unredact` turns redacted data back into the plaintext this product exists
to protect. That it happened, and who asked, is worth a durable record.

Three things here are easy to get wrong in ways that leave the suite green.

**The record must not name the vault.** Not its id, not a hash of it, not its
owning policy. `/v1/activity` is admin-role and globally unfiltered, and admin
outranks api, so one credential can both probe this endpoint and read every
record. A hash does not help -- the prober supplied the id. Recording the probed
vault's owner is worst of all: it turns a uniform 404 into a definitive
statement that the id exists and names who holds it.

**A device is not an API key.** Authentication sets `api_key_id = None` for a
device credential and `device_id` instead, so a helper reading only the former
attributed every device attempt to nobody -- and a device attempting reversal is
among the most interesting refusals there is.

**The exits cannot be enumerated.** Successive drafts audited one exit, then six,
and each review found another the previous had missed. The refusal record is
written by middleware, which observes the response rather than anticipating
where it came from, so the tests below deliberately include outcomes the ROUTE
never produces.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from app.db.models import ActivityLog, Policy, RuleSet
from app.unredact_audit_middleware import UnredactAuditMiddleware
from app.validation_errors import install

from .test_guard_routes import _make_app_and_client

SECRET = "jon@example.com"


@pytest.fixture
def env():
    client, _admin, api_key, _viewer, session_factory = _make_app_and_client()
    client.app.add_middleware(UnredactAuditMiddleware)
    install(client.app)
    from app.routes import unredact

    client.app.include_router(unredact.router)
    with session_factory() as session:
        policy = session.query(Policy).filter_by(is_default=True).one()
        session.query(RuleSet).filter_by(policy_id=policy.id).count()
        session.commit()
    return TestClient(client.app, raise_server_exceptions=False), api_key, session_factory


def _audit_rows(session_factory):
    with session_factory() as session:
        return session.query(ActivityLog).filter(ActivityLog.action.like("unredact%")).all()


def _post(client, key, body):
    return client.post("/v1/unredact", json=body, headers={"Authorization": f"Bearer {key}"})


def _ctx(vault_id: str) -> str:
    return base64.b64encode(json.dumps({"vault_id": vault_id}).encode()).decode()


# --- what a row must never carry ------------------------------------------


def test_no_row_names_the_vault(env):
    """Assert on the stored ROW, not the call site, so a field added later
    cannot slip past."""
    client, key, session_factory = env
    vault_id = "vlt-canary-9f3a2c"

    _post(client, key, {"fpe_context": _ctx(vault_id), "redacted_data": "x"})

    rows = _audit_rows(session_factory)
    assert rows, "a refused reversal must be recorded"
    blob = json.dumps([{c.name: getattr(r, c.name) for c in r.__table__.columns} for r in rows], default=str)
    assert vault_id not in blob
    import hashlib

    assert hashlib.sha256(vault_id.encode()).hexdigest()[:16] not in blob


# --- every exit, including ones the route does not produce ------------------


EXITS = {
    "schema rejection, before the route runs": ({"fpe_context": 123}, 422),
    "malformed base64": ({"fpe_context": "!!!", "redacted_data": "x"}, 400),
    "no vault_id in the context": ({"fpe_context": base64.b64encode(b"{}").decode(), "redacted_data": "x"}, 400),
    "no such vault": ({"fpe_context": _ctx("absent"), "redacted_data": "x"}, 404),
}


@pytest.mark.parametrize("name,case", EXITS.items(), ids=list(EXITS))
def test_every_refusal_is_recorded(env, name, case):
    body, expected_status = case
    client, key, session_factory = env
    before = len(_audit_rows(session_factory))

    response = _post(client, key, body)

    assert response.status_code == expected_status, name
    rows = _audit_rows(session_factory)
    assert len(rows) == before + 1, f"{name} produced no audit row"
    assert rows[-1].action == "unredact_refused"


def test_the_schema_rejection_is_the_one_enumeration_would_miss(env):
    """It never reaches the route, so no call placed at a route exit sees it.

    This is the case that distinguishes observing the response from listing the
    places a response can come from.
    """
    client, key, session_factory = env
    before = len(_audit_rows(session_factory))
    assert _post(client, key, {"fpe_context": 123}).status_code == 422
    assert len(_audit_rows(session_factory)) == before + 1


# --- the actor --------------------------------------------------------------


def test_the_actor_is_named_and_typed(env):
    """A kind and an id, so a credential type added later is a visible gap
    rather than a silent "unknown"."""
    client, key, session_factory = env
    _post(client, key, {"fpe_context": "!!!", "redacted_data": "x"})
    actor = _audit_rows(session_factory)[-1].actor
    assert actor.startswith("api_key:"), actor
    assert actor != "api_key:None"


def test_a_device_is_not_recorded_as_an_unknown_caller():
    """Authentication sets api_key_id = None for a device and device_id instead.

    A helper reading only the former attributed every device attempt to nobody,
    and a device attempting reversal is among the most interesting refusals
    there is.
    """
    from app.services.unredact_audit import actor_for

    class _DeviceState:
        device_id = "dev_abc123"
        api_key_id = None
        policy_id = "pol_x"

    assert actor_for(_DeviceState()) == ("device", "dev_abc123")

    class _KeyState:
        device_id = None
        api_key_id = "ak_9"
        policy_id = "pol_x"

    assert actor_for(_KeyState()) == ("api_key", "ak_9")


# --- the split guarantee ----------------------------------------------------


def test_a_failing_audit_does_not_change_a_refusal(env, monkeypatch):
    """The caller received nothing either way, so a failed log must not inflate
    their 400 into a 500."""
    client, key, session_factory = env
    from app.services.activity_service import ActivityService

    monkeypatch.setattr(ActivityService, "log", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))
    assert _post(client, key, {"fpe_context": "!!!", "redacted_data": "x"}).status_code == 400


# --- the disclosure half ----------------------------------------------------
#
# A reversal that discloses data is recorded, or it does not happen. The
# plaintext exists in the handler and has NOT yet reached the caller, which is
# the only moment that choice is available: middleware sees the response with the
# data already in it.


@pytest.fixture
def sealed():
    """A real vault, sealed under a real keyring, reachable by a bound key."""
    import base64 as b64
    import secrets

    from fastapi import FastAPI

    from app.auth.key_utils import generate_key, hash_key, key_prefix
    from app.auth.middleware import AuthMiddleware
    from app.config import Settings
    from app.db.engine import get_engine, get_session_factory
    from app.db.models import APIKey, Base
    from app.vault_crypto import Keyring
    from app.vault_manager import VaultManager

    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = get_session_factory(engine)

    raw = generate_key(prefix="ak")
    with session_factory() as session:
        session.add(Policy(id="pol_a", name="pol_a", type="application"))
        session.add(
            APIKey(
                name="k",
                key_hash=hash_key(raw),
                key_prefix=key_prefix(raw),
                role="api",
                policy_id="pol_a",
            )
        )
        session.commit()

    ring = Keyring.from_settings(
        Settings(
            VAULT_ENCRYPTION_KEYS=f"k1:{b64.b64encode(secrets.token_bytes(32)).decode()}",
            VAULT_ENCRYPTION_CURRENT="k1",
        )
    )
    manager = VaultManager(session_factory, keyring=ring)
    vault_id, vault = manager.create_vault()
    placeholder = vault.store("EMAIL_ADDRESS", SECRET)
    assert manager.save(vault_id, vault, "pol_a") is True

    app = FastAPI()
    app.add_middleware(UnredactAuditMiddleware)
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = session_factory
    app.state.vault_manager = VaultManager(session_factory, keyring=ring)
    from app.routes import unredact as unredact_route

    app.include_router(unredact_route.router)
    return TestClient(app, raise_server_exceptions=False), raw, session_factory, vault_id, placeholder


def test_a_successful_reversal_is_recorded(sealed):
    """The positive control. Without it, refusing every reversal would satisfy
    the fail-closed test below."""
    client, key, session_factory, vault_id, placeholder = sealed

    response = _post(client, key, {"fpe_context": _ctx(vault_id), "redacted_data": placeholder})

    assert response.status_code == 200
    assert response.json()["result"]["data"] == SECRET
    rows = _audit_rows(session_factory)
    assert rows and rows[-1].action == "unredact", "a disclosure went unrecorded"
    assert rows[-1].target_id == response.json()["request_id"], "the row names a different attempt"


def test_an_unrecordable_reversal_does_not_happen(sealed, monkeypatch):
    """If the server cannot record that PII was disclosed, it must not disclose.

    The vault outlives the request, so a caller who retries after the database
    recovers gets their data.
    """
    client, key, session_factory, vault_id, placeholder = sealed
    from app.services.activity_service import ActivityService

    monkeypatch.setattr(ActivityService, "log", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))

    response = _post(client, key, {"fpe_context": _ctx(vault_id), "redacted_data": placeholder})

    assert response.status_code == 500
    assert SECRET not in response.text, "the plaintext left despite going unrecorded"


def test_the_vault_survives_so_a_retry_succeeds(sealed, monkeypatch):
    """Refusing must not also destroy the mapping, or the failure would be
    permanent rather than transient."""
    client, key, session_factory, vault_id, placeholder = sealed
    from app.services.activity_service import ActivityService

    real = ActivityService.log
    monkeypatch.setattr(ActivityService, "log", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))
    assert _post(client, key, {"fpe_context": _ctx(vault_id), "redacted_data": placeholder}).status_code == 500

    monkeypatch.setattr(ActivityService, "log", real)
    retry = _post(client, key, {"fpe_context": _ctx(vault_id), "redacted_data": placeholder})
    assert retry.status_code == 200
    assert retry.json()["result"]["data"] == SECRET


# --- the three a review found ----------------------------------------------


def test_an_exception_escaping_the_route_is_still_recorded(sealed, monkeypatch):
    """The case the design named and the first implementation missed.

    `get_vault` deliberately propagates AuthenticationFailed and UnknownKey --
    a caller presenting a vault this server cannot open must be loud, not
    silent. That exception UNWINDS through the audit middleware on its way to
    the error handler, which turns it into a 500 further out, so middleware that
    waits for a response never sees it.
    """
    client, key, session_factory, vault_id, placeholder = sealed
    from app.vault_crypto import AuthenticationFailed
    from app.vault_manager import VaultManager

    monkeypatch.setattr(
        VaultManager,
        "get_vault",
        lambda *a, **k: (_ for _ in ()).throw(AuthenticationFailed("altered row")),
    )
    before = len(_audit_rows(session_factory))

    response = _post(client, key, {"fpe_context": _ctx(vault_id), "redacted_data": placeholder})

    assert response.status_code == 500
    rows = _audit_rows(session_factory)
    assert len(rows) == before + 1, "an escaping exception went unrecorded"
    assert rows[-1].action == "unredact_refused"


def test_the_helper_survives_a_session_that_will_not_close():
    """A raise from `finally` happens AFTER the except that swallows it, so
    without its own guard it escapes -- replacing a refusal the middleware
    promised not to touch, or turning the handler's deliberate 500 into an
    unhandled one.

    Asserted on the helper directly. Two attempts to prove this through a
    request failed for the same reason twice: `AuthMiddleware` opens and closes
    a session from the same factory, so breaking `close` at any level a request
    can see also breaks authentication, and the test then turns on somebody
    else's cleanup. The helper is the only thing that can be isolated here, and
    it is the thing the claim is about.
    """
    from app.db.engine import get_engine, get_session_factory
    from app.db.models import Base
    from app.services.unredact_audit import record_unredact

    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = get_session_factory(engine)

    class _RefusesToClose:
        def __init__(self, real):
            self._real = real

        def __getattr__(self, name):
            return getattr(self._real, name)

        def close(self):
            raise RuntimeError("connection gone")

    class _Request:
        class state:
            device_id = None
            api_key_id = "ak_1"
            policy_id = "pol_a"

        class app:
            class state:
                session_factory = staticmethod(lambda: _RefusesToClose(factory()))

    # Returns rather than raises, and reports the row it did write.
    assert record_unredact(_Request, "tw_abc", ok=False) is True


def test_a_reversal_that_reveals_nothing_is_not_recorded_as_one(sealed):
    """200 does not mean disclosed.

    A caller can hold a valid vault id and submit text containing none of its
    placeholders. That request succeeds having revealed nothing, and recording
    it as a reversal would attest to a plaintext recovery that did not happen.
    An audit trail that overstates is worse than one that is merely incomplete.
    """
    client, key, session_factory, vault_id, placeholder = sealed

    response = _post(client, key, {"fpe_context": _ctx(vault_id), "redacted_data": "nothing to replace here"})

    assert response.status_code == 200
    assert response.json()["result"]["data"] == "nothing to replace here"
    rows = _audit_rows(session_factory)
    assert rows, "the attempt was not recorded at all"
    assert rows[-1].action == "unredact_refused", "a request that revealed nothing was recorded as a reversal"


def test_a_reversal_that_reveals_nothing_is_not_refused_when_the_audit_fails(sealed, monkeypatch):
    """Fail-closed applies to disclosure, not to every 200.

    Refusing here would deny a caller a response that gave them nothing anyway.
    """
    client, key, session_factory, vault_id, placeholder = sealed
    from app.services.activity_service import ActivityService

    monkeypatch.setattr(ActivityService, "log", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))

    response = _post(client, key, {"fpe_context": _ctx(vault_id), "redacted_data": "nothing to replace here"})

    assert response.status_code == 200


def test_one_attempt_never_produces_two_rows(sealed, monkeypatch):
    """The handler records its own outcome; the middleware must not record again.

    A failed disclosure audit makes the route answer 500, which the middleware
    then sees as a non-200 and would record as a refusal -- for the same attempt
    the handler had just tried to record as a disclosure. In the worst case the
    commit succeeded and then raised, so an `unredact` row is already on disk
    while the plaintext was withheld, and an `unredact_refused` beside it has
    the trail asserting both about a request that disclosed nothing.
    """
    client, key, session_factory, vault_id, placeholder = sealed
    from app.services.activity_service import ActivityService

    committed: list[str] = []
    real_log = ActivityService.log

    def commits_then_fails(self, **kwargs):
        real_log(self, **kwargs)  # the row lands
        committed.append(kwargs["action"])
        raise RuntimeError("connection lost after commit")

    monkeypatch.setattr(ActivityService, "log", commits_then_fails)
    before = len(_audit_rows(session_factory))

    response = _post(client, key, {"fpe_context": _ctx(vault_id), "redacted_data": placeholder})

    assert response.status_code == 500
    assert SECRET not in response.text
    rows = _audit_rows(session_factory)
    assert (
        len(rows) - before == 1
    ), f"one attempt produced {len(rows) - before} rows: {[r.action for r in rows[before:]]}"


def test_a_request_the_handler_never_reached_is_still_recorded(env):
    """The claim is only made by the handler, so an attempt refused before it --
    a schema rejection, a dependency -- is still the middleware's to record.

    Without this, deferring to the handler would silently drop every refusal
    that never got there.
    """
    client, key, session_factory = env
    before = len(_audit_rows(session_factory))
    assert _post(client, key, {"fpe_context": 123}).status_code == 422
    assert len(_audit_rows(session_factory)) == before + 1
