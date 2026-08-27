"""Integration tests for device management routes and auth middleware token handling."""

from __future__ import annotations

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
from app.db.models import AccessToken, APIKey, Base, Policy, RegistrationToken


def _iid(label: str) -> str:
    """A realistic installation ID.

    The API requires at least 16 characters of entropy, so a guessable value
    cannot be squatted to deny someone else enrolment. Deterministic per label
    so tests stay readable.
    """
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, label))


# Registration tokens must name a policy that exists, so the fixture seeds one
# with a known id rather than every test having to create its own.
TEST_POLICY_ID = "test-policy"


def _make_app_and_client():
    """Create an in-memory SQLite app with all routers and auth middleware."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = SessionLocal

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    from app.routes import devices, keys, registration

    app.include_router(registration.router)
    app.include_router(devices.router)
    app.include_router(keys.router)

    # Create an admin API key
    raw_admin_key = generate_key(prefix="ak")
    session = SessionLocal()
    admin_key = APIKey(
        name="test-admin",
        key_hash=hash_key(raw_admin_key),
        key_prefix=key_prefix(raw_admin_key),
        role="admin",
    )
    session.add(admin_key)
    session.add(Policy(id=TEST_POLICY_ID, name="test-policy", type="application"))
    session.commit()
    session.close()

    client = TestClient(app)
    return client, raw_admin_key, SessionLocal


@pytest.fixture
def setup():
    client, admin_key, session_factory = _make_app_and_client()
    return client, admin_key, session_factory


# ------------------------------------------------------------------
# Registration token CRUD
# ------------------------------------------------------------------


def test_create_registration_token_admin(setup):
    client, admin_key, _ = setup
    resp = client.post(
        "/v1/registration-tokens",
        json={
            "name": "test-rt",
            "policy_id": TEST_POLICY_ID,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "test-rt"
    assert "token" in data
    assert data["token"].startswith("rt_")
    assert "token_prefix" in data


def test_create_registration_token_viewer_forbidden(setup):
    client, admin_key, session_factory = setup
    # Create a viewer key
    raw_viewer = generate_key(prefix="ak")
    session = session_factory()
    viewer_key = APIKey(
        name="test-viewer",
        key_hash=hash_key(raw_viewer),
        key_prefix=key_prefix(raw_viewer),
        role="viewer",
    )
    session.add(viewer_key)
    session.commit()
    session.close()

    resp = client.post(
        "/v1/registration-tokens",
        json={
            "name": "nope",
            "policy_id": TEST_POLICY_ID,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers={"Authorization": f"Bearer {raw_viewer}"},
    )
    assert resp.status_code == 403


def test_list_registration_tokens(setup):
    client, admin_key, _ = setup
    # Create two tokens
    client.post(
        "/v1/registration-tokens",
        json={
            "name": "rt-1",
            "policy_id": TEST_POLICY_ID,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    client.post(
        "/v1/registration-tokens",
        json={
            "name": "rt-2",
            "policy_id": TEST_POLICY_ID,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    resp = client.get(
        "/v1/registration-tokens",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    assert len(resp.json()) >= 2


def test_delete_registration_token(setup):
    client, admin_key, _ = setup
    create_resp = client.post(
        "/v1/registration-tokens",
        json={
            "name": "to-delete",
            "policy_id": TEST_POLICY_ID,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    token_id = create_resp.json()["id"]
    del_resp = client.delete(
        f"/v1/registration-tokens/{token_id}",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert del_resp.status_code == 204


# ------------------------------------------------------------------
# Device check (register + refresh)
# ------------------------------------------------------------------


def _create_rt_token(client, admin_key):
    """Helper: create an rt_ token and return the raw token string."""
    resp = client.post(
        "/v1/registration-tokens",
        json={
            "name": "device-rt",
            "policy_id": TEST_POLICY_ID,
            # Required since keys became bounded.
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            # Pre-authorized: these tests are about refresh, revocation and
            # listing, not about approval. The pending default is pinned by the
            # approval tests, which omit this field.
            "pre_authorized": True,
        },
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    return resp.json()["token"]


def _enrol_device(client, rt_token, installation_id=_iid("inst-abc-123"), fingerprint="fp-abc-123"):
    return client.post(
        "/v1/devices/enrol",
        json={
            "installation_id": installation_id,
            "fingerprint": fingerprint,
            "device_name": "Test Laptop",
            "user_name": "alice",
            "user_email": "alice@example.com",
            "browser": "Chrome",
            "os": "macOS",
            "extension_version": "1.0.0",
        },
        headers={"Authorization": f"Bearer {rt_token}"},
    )


def test_enrol_registers_new_device(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    resp = _enrol_device(client, rt_token)
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "Success"
    assert "access_token" in data["result"]
    at = data["result"]["access_token"]
    assert at["token"].startswith("at_")
    assert at["expires_in"] == 3600


def test_refresh_with_the_devices_own_token_returns_a_new_one(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    enrolled = _enrol_device(client, rt_token, installation_id=_iid("inst-refresh-1")).json()["result"]
    at1 = enrolled["access_token"]["token"]

    resp = client.post(
        f"/v1/devices/{enrolled['device_id']}/refresh",
        json={"device_name": "Renamed"},
        headers={"Authorization": f"Bearer {at1}"},
    )

    assert resp.status_code == 200
    assert resp.json()["result"]["access_token"]["token"] != at1


def test_a_registration_token_cannot_refresh(setup):
    """rt_ is constrained to enrolment; it must not reach a refresh."""
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    enrolled = _enrol_device(client, rt_token, installation_id=_iid("inst-victim")).json()["result"]

    resp = client.post(
        f"/v1/devices/{enrolled['device_id']}/refresh",
        json={},
        headers={"Authorization": f"Bearer {rt_token}"},
    )

    assert resp.status_code == 403


def test_another_devices_token_cannot_refresh(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    victim = _enrol_device(client, rt_token, installation_id=_iid("inst-victim2")).json()["result"]
    attacker = _enrol_device(client, rt_token, installation_id=_iid("inst-attacker")).json()["result"]

    resp = client.post(
        f"/v1/devices/{victim['device_id']}/refresh",
        json={},
        headers={"Authorization": f"Bearer {attacker['access_token']['token']}"},
    )

    assert resp.status_code == 403


def test_at_token_works_for_guard_like_call(setup):
    """An at_ token should resolve to role=api and allow viewer-level access."""
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    resp = _enrol_device(client, rt_token)
    at_token = resp.json()["result"]["access_token"]["token"]

    # Use the at_ token to list devices (requires viewer role; at_ gives api role)
    # api role (level 1) < viewer (level 2) — so this should be 403
    resp2 = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {at_token}"},
    )
    assert resp2.status_code == 403  # api < viewer


def test_list_devices_with_admin(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    _enrol_device(client, rt_token)

    resp = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    devices = resp.json()
    assert len(devices) >= 1
    assert devices[0]["fingerprint"] == "fp-abc-123"


def test_patch_device_status(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    _enrol_device(client, rt_token)

    devices = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {admin_key}"},
    ).json()
    device_id = devices[0]["id"]

    resp = client.patch(
        f"/v1/devices/{device_id}",
        json={"status": "revoked"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"


def test_delete_device(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    _enrol_device(client, rt_token)

    devices = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {admin_key}"},
    ).json()
    device_id = devices[0]["id"]

    resp = client.delete(
        f"/v1/devices/{device_id}",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 204


# ------------------------------------------------------------------
# Auth middleware guards
# ------------------------------------------------------------------


def test_rt_token_rejected_for_non_check_path(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)

    # Try to list devices with an rt_ token — should be 403
    resp = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {rt_token}"},
    )
    assert resp.status_code == 403


def test_rt_token_rejected_for_keys_path(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)

    resp = client.get(
        "/v1/keys",
        headers={"Authorization": f"Bearer {rt_token}"},
    )
    assert resp.status_code == 403


def test_at_token_rejected_for_admin_only_paths(setup):
    """at_ tokens resolve to role=api which should not access admin endpoints."""
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    resp = _enrol_device(client, rt_token)
    at_token = resp.json()["result"]["access_token"]["token"]

    # Try to create a registration token (admin only)
    resp2 = client.post(
        "/v1/registration-tokens",
        json={
            "name": "nope",
            "policy_id": TEST_POLICY_ID,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers={"Authorization": f"Bearer {at_token}"},
    )
    assert resp2.status_code == 403


def test_revoked_device_at_token_rejected(setup):
    """After revoking a device, its at_ token should be rejected."""
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    resp = _enrol_device(client, rt_token)
    at_token = resp.json()["result"]["access_token"]["token"]

    # Revoke the device
    devices = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {admin_key}"},
    ).json()
    device_id = devices[0]["id"]
    client.patch(
        f"/v1/devices/{device_id}",
        json={"status": "revoked"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )

    # Try using the at_ token — should fail because device is inactive
    resp2 = client.get(
        "/v1/devices",
        headers={"Authorization": f"Bearer {at_token}"},
    )
    assert resp2.status_code == 401


def test_invalid_token_rejected(setup):
    client, _, _ = setup
    resp = client.get(
        "/v1/devices",
        headers={"Authorization": "Bearer ak_bogus_invalid_key"},
    )
    assert resp.status_code == 401


def test_missing_auth_header_rejected(setup):
    client, _, _ = setup
    resp = client.get("/v1/devices")
    assert resp.status_code == 401


def test_health_bypasses_auth(setup):
    client, _, _ = setup
    resp = client.get("/health")
    assert resp.status_code == 200


# ------------------------------------------------------------------
# The enrolment contract
# ------------------------------------------------------------------


def test_a_registration_token_must_name_a_policy(setup):
    """Without this the column existed but nothing ever wrote it."""
    client, admin_key, _ = setup
    resp = client.post(
        "/v1/registration-tokens",
        json={"name": "unscoped"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 422


def test_a_registration_token_policy_must_exist(setup):
    client, admin_key, _ = setup
    resp = client.post(
        "/v1/registration-tokens",
        json={
            "name": "bad-policy",
            "policy_id": "no-such-policy",
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 400


def test_the_created_token_reports_its_policy(setup):
    client, admin_key, _ = setup
    resp = client.post(
        "/v1/registration-tokens",
        json={
            "name": "scoped",
            "policy_id": TEST_POLICY_ID,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.json()["policy_id"] == TEST_POLICY_ID


def test_an_enrolled_device_inherits_the_tokens_policy_end_to_end(setup):
    """Producer and consumer, both through the real API."""
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)

    enrolled = _enrol_device(client, rt_token, installation_id=_iid("inst-scoped-e2e")).json()["result"]

    devices = client.get("/v1/devices", headers={"Authorization": f"Bearer {admin_key}"}).json()
    device = next(d for d in devices if d["id"] == enrolled["device_id"])
    assert device["policy_id"] == TEST_POLICY_ID


def test_enrolling_an_already_enrolled_installation_is_a_conflict(setup):
    """409, not a 201 carrying a failure in the body: nothing was created."""
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    _enrol_device(client, rt_token, installation_id=_iid("inst-duplicate"))

    resp = _enrol_device(client, rt_token, installation_id=_iid("inst-duplicate"))

    assert resp.status_code == 409


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "short",
        "has spaces in it here",
        "x" * 129,
        "semi;colons;here!!",
        "alice-laptop-2026",  # plausible, memorable, entirely predictable
        "aaaaaaaaaaaaaaaa",  # long enough to pass a length floor, no entropy
        "00000000-0000-0000-0000-000000000000",  # the nil UUID
        "6ba7b810-9dad-11d1-80b4-00c04fd430",  # UUID-ish but malformed
    ],
)
def test_a_non_uuid_installation_id_is_rejected(setup, bad):
    """The server checks the form of the identifier, not its randomness.

    It cannot do the latter — it sees only the result. Requiring a UUID rules
    out the obviously weak values a free-text field allowed and gives clients
    one unambiguous contract. Enrolment is first-claim and never reassigns, so
    anyone able to predict an installation ID can enrol it first and lock the
    genuine client out; that residual risk lives in the client's generator.
    """
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)

    resp = _enrol_device(client, rt_token, installation_id=bad)

    assert resp.status_code == 422


def test_a_rotated_token_cannot_refresh_again_over_http(setup):
    """The replay defect, at the route."""
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    enrolled = _enrol_device(client, rt_token, installation_id=_iid("inst-replay")).json()["result"]
    first = enrolled["access_token"]["token"]
    device_id = enrolled["device_id"]

    ok = client.post(f"/v1/devices/{device_id}/refresh", json={}, headers={"Authorization": f"Bearer {first}"})
    assert ok.status_code == 200

    replay = client.post(f"/v1/devices/{device_id}/refresh", json={}, headers={"Authorization": f"Bearer {first}"})
    assert replay.status_code == 403


def test_refreshing_a_revoked_device_is_forbidden(setup):
    client, admin_key, _ = setup
    rt_token = _create_rt_token(client, admin_key)
    enrolled = _enrol_device(client, rt_token, installation_id=_iid("inst-revoked-refresh")).json()["result"]
    at_token = enrolled["access_token"]["token"]

    client.patch(
        f"/v1/devices/{enrolled['device_id']}",
        json={"status": "revoked"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )

    resp = client.post(
        f"/v1/devices/{enrolled['device_id']}/refresh",
        json={},
        headers={"Authorization": f"Bearer {at_token}"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Registration token expiry
#
# The rt_ branch of the middleware read expires_at straight off the row and
# compared it to an aware now(). SQLite has no timezone type, so the column
# comes back naive and the comparison raises instead of returning a verdict.
#
# No existing test set an expiry -- test_device_service asserts it is None --
# so the whole path was unexercised while the suite stayed green.
# ---------------------------------------------------------------------------


def _enrol(client, raw_token: str, label: str):
    return client.post(
        "/v1/devices/enrol",
        headers={"Authorization": f"Bearer {raw_token}"},
        json={
            "installation_id": _iid(label),
            "device_name": "d",
            "user_name": "u",
            "user_email": "u@example.com",
            "browser": "b",
            "os": "o",
            "extension_version": "1",
        },
    )


def _seed_token(session_factory, *, expires_at) -> str:
    raw = generate_key(prefix="rt")
    session = session_factory()
    session.add(
        RegistrationToken(
            name="expiry-fixture",
            token_hash=hash_key(raw),
            token_prefix=key_prefix(raw),
            policy_id=TEST_POLICY_ID,
            expires_at=expires_at,
        )
    )
    session.commit()
    session.close()
    return raw


def test_registration_token_with_an_expiry_can_enrol(setup):
    """A token with a future expiry must work.

    A time-limited onboarding key is the security-conscious choice, and it was
    the one that did not function.
    """
    client, _admin_key, session_factory = setup
    raw = _seed_token(session_factory, expires_at=datetime.now(UTC) + timedelta(days=1))

    response = _enrol(client, raw, "expiring-token")

    assert response.status_code == 201


def test_expired_registration_token_is_refused_not_crashed(setup):
    """An expired token is a 401. A 500 is not a verdict."""
    client, _admin_key, session_factory = setup
    raw = _seed_token(session_factory, expires_at=datetime.now(UTC) - timedelta(seconds=1))

    response = _enrol(client, raw, "expired-token")

    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_an_expired_access_token_is_rejected_by_the_middleware(setup):
    """The middleware must refuse an expired at_ token, not merely the service.

    Found by mutation: deleting the expiry check in _handle_at_token entirely
    left all 1496 tests passing. The check was correct and nothing proved it,
    which is exactly how the sibling rt_ comparison six lines above came to be
    broken without the suite noticing.

    Asserting 401 rather than "some rejection" is the point. refresh_device
    checks expiry again for itself and answers 403, so a test that accepted any
    4xx would pass with the middleware guard removed -- and every OTHER route a
    device token reaches has no second check at all.
    """
    client, admin_key, session_factory = setup
    rt_token = _create_rt_token(client, admin_key)
    enrolled = _enrol_device(client, rt_token, installation_id=_iid("inst-expired-at")).json()["result"]
    at_token = enrolled["access_token"]["token"]
    device_id = enrolled["device_id"]

    session = session_factory()
    session.query(AccessToken).filter_by(token_hash=hash_key(at_token)).update(
        {"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    session.commit()
    session.close()

    response = client.post(
        f"/v1/devices/{device_id}/refresh",
        json={},
        headers={"Authorization": f"Bearer {at_token}"},
    )

    assert response.status_code == 401, "the middleware let an expired credential through"
    assert "expired" in response.json()["detail"].lower()


def test_the_device_listing_never_publishes_the_confirmation_code(setup):
    """The code is the one field an approver holds that a claimant cannot supply.

    The listing is readable by `viewer`. Publishing the code there would collapse
    approval back to "device id alone", which is the thing the code exists to
    prevent -- and it would do so without changing a single line of the approval
    check, so nothing else in this suite would notice.
    """
    client, admin_key, session_factory = setup
    # Its own token, NOT the shared pre-authorized helper: a pre-authorized
    # device has no code, so this test would assert nothing.
    rt = client.post(
        "/v1/registration-tokens",
        json={
            "name": "needs-approval",
            "policy_id": TEST_POLICY_ID,
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    enrolled = _enrol_device(client, rt.json()["token"], installation_id=_iid("inst-no-leak")).json()["result"]
    code = enrolled["confirmation_code"]
    assert code, "fixture produced no code; the test would pass vacuously"

    listing = client.get("/v1/devices", headers={"Authorization": f"Bearer {admin_key}"})

    assert listing.status_code == 200
    body = listing.text
    assert code not in body, "the confirmation code was published in the device listing"
    for device in listing.json():
        assert "confirmation_code" not in device
