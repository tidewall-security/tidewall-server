"""Bounds on the two device endpoints a stranger can reach.

Rate limiting only slows unbounded state; it does not bound it. The quota bounds
it, the reaper recovers it, and the limiter keeps the path from being a cheap
write amplifier.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.auth.key_utils import hash_key
from app.db.engine import get_engine, get_session_factory
from app.db.models import Base, Device, Policy, RegistrationToken
from app.enrolment_rate_limit import EnrolmentRateLimitMiddleware
from app.services.device_service import MAX_PENDING_PER_TOKEN, DeviceService
from app.services.enrolment_limits import EnrolmentLimits, RateLimited, source_ip

_META = {
    "device_name": "d",
    "user_name": "u",
    "user_email": "u@example.com",
    "browser": "b",
    "os": "o",
    "ext_version": "1",
}


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = get_session_factory(engine)()
    session.add(Policy(id="p", name="p", type="application"))
    session.commit()
    yield session
    session.close()


def _key(session, *, pre_authorized: bool = False, max_uses=None):
    return DeviceService(session).create_registration_token(
        name="k",
        policy_id="p",
        expires_at=datetime.now(UTC) + timedelta(days=1),
        max_uses=max_uses,
        pre_authorized=pre_authorized,
    )


# ---------------------------------------------------------------------------
# The limiter runs before the body is read
# ---------------------------------------------------------------------------


def _limited_app(per_minute: int = 3):
    app = FastAPI()
    app.state.enrolment_limits = EnrolmentLimits(per_minute)
    app.state.trusted_proxy_hops = 0
    app.add_middleware(EnrolmentRateLimitMiddleware)

    class Body(BaseModel):
        installation_id: str

    @app.post("/v1/devices/enrol")
    async def enrol(body: Body):
        return {"ok": True}

    return TestClient(app)


def test_the_limit_rejects_before_the_body_is_read():
    """A FastAPI dependency would not.

    JSON decoding precedes dependency solving -- a malformed body returns 422
    with the dependency never running -- and the flood case IS malformed and
    oversized bodies. A limiter in a dependency would be measured by a test
    asserting a control it does not have.
    """
    client = _limited_app(per_minute=3)
    statuses = [
        client.post(
            "/v1/devices/enrol",
            content=b"{" * 10_000,
            headers={"Content-Type": "application/json"},
        ).status_code
        for _ in range(8)
    ]

    assert 429 in statuses, "the flood was never limited"
    # 422 would mean FastAPI decoded the malformed body first: the limiter is
    # too late, and the expensive path is the one being flooded.
    assert statuses[-1] == 429, f"last response was {statuses[-1]}, not a rejection"


def test_the_limit_covers_refresh_as_well_as_enrolment():
    """Refresh is reachable with a credential that does not exist.

    Its middleware branch deliberately leaves adjudication to the service so
    device state can dominate credential state, which means an unknown token
    still reaches the route. Unbounded, that is an unmetered oracle.
    """
    limits = EnrolmentLimits(per_minute=2)
    limits.check("1.2.3.4", "/v1/devices/abc/refresh")
    limits.check("1.2.3.4", "/v1/devices/abc/refresh")

    with pytest.raises(RateLimited):
        limits.check("1.2.3.4", "/v1/devices/abc/refresh")


def test_enrolment_and_refresh_have_separate_allowances():
    limits = EnrolmentLimits(per_minute=1)
    limits.check("1.2.3.4", "/v1/devices/enrol")
    limits.check("1.2.3.4", "/v1/devices/abc/refresh")  # must not be refused


def test_an_unattributable_caller_shares_one_bucket_rather_than_escaping():
    """No source is not a licence."""
    limits = EnrolmentLimits(per_minute=1)
    limits.check(None, "/v1/devices/enrol")

    with pytest.raises(RateLimited):
        limits.check(None, "/v1/devices/enrol")


# ---------------------------------------------------------------------------
# Source attribution
# ---------------------------------------------------------------------------


def test_forwarded_headers_are_ignored_when_no_proxy_is_trusted():
    """The header is caller-supplied. Trusting it means every request can claim
    a fresh identity and the limit bounds nothing at all."""
    assert source_ip("10.0.0.1", "1.1.1.1, 2.2.2.2", trusted_hops=0) == "10.0.0.1"


def test_only_the_trusted_number_of_hops_is_believed():
    # One trusted proxy: believe the entry it appended, which is the rightmost.
    assert source_ip("10.0.0.1", "9.9.9.9, 8.8.8.8, 7.7.7.7", trusted_hops=1) == "7.7.7.7"
    # Two: one further left.
    assert source_ip("10.0.0.1", "9.9.9.9, 8.8.8.8, 7.7.7.7", trusted_hops=2) == "8.8.8.8"
    # More hops trusted than present: take the leftmost, never index out.
    assert source_ip("10.0.0.1", "9.9.9.9", trusted_hops=5) == "9.9.9.9"


# ---------------------------------------------------------------------------
# The pending quota
# ---------------------------------------------------------------------------


def test_pending_quota_is_enforced_per_token(db_session):
    raw, _rt = _key(db_session)
    service = DeviceService(db_session)
    for n in range(MAX_PENDING_PER_TOKEN):
        assert (
            service.enrol_device(rt_token_hash=hash_key(raw), installation_id=f"i{n}", **_META)["status"] == "Success"
        )

    over = service.enrol_device(rt_token_hash=hash_key(raw), installation_id="over", **_META)

    assert over["status"] == "PendingQuotaExceeded"
    assert db_session.query(Device).count() == MAX_PENDING_PER_TOKEN


def test_approved_devices_do_not_count_against_the_pending_quota(db_session):
    """The quota bounds unapproved state, not fleet size."""
    raw, rt = _key(db_session)
    service = DeviceService(db_session)
    result = service.enrol_device(rt_token_hash=hash_key(raw), installation_id="i0", **_META)
    db_session.expire_all()
    assert db_session.get(RegistrationToken, rt.id).pending_count == 1

    service.approve_device(result["result"]["device_id"], result["result"]["confirmation_code"])

    db_session.expire_all()
    assert db_session.get(RegistrationToken, rt.id).pending_count == 0


def test_a_pre_authorized_key_does_not_consume_pending_slots(db_session):
    raw, rt = _key(db_session, pre_authorized=True)
    DeviceService(db_session).enrol_device(rt_token_hash=hash_key(raw), installation_id="i0", **_META)

    db_session.expire_all()
    assert db_session.get(RegistrationToken, rt.id).pending_count == 0


def test_a_full_quota_recovers_once_the_devices_are_approved(db_session):
    """A counter that only rises is a quota that eventually refuses everything."""
    raw, rt = _key(db_session)
    service = DeviceService(db_session)
    ids = []
    for n in range(MAX_PENDING_PER_TOKEN):
        r = service.enrol_device(rt_token_hash=hash_key(raw), installation_id=f"i{n}", **_META)
        ids.append((r["result"]["device_id"], r["result"]["confirmation_code"]))
    assert (
        service.enrol_device(rt_token_hash=hash_key(raw), installation_id="over", **_META)["status"]
        == "PendingQuotaExceeded"
    )

    for device_id, code in ids:
        service.approve_device(device_id, code)

    db_session.expire_all()
    assert db_session.get(RegistrationToken, rt.id).pending_count == 0
    assert service.enrol_device(rt_token_hash=hash_key(raw), installation_id="after", **_META)["status"] == "Success"


def test_two_concurrent_enrolments_cannot_share_the_last_pending_slot(tmp_path):
    """Check-then-insert is not a bound: SQLite serialises the writes, not the
    reads before them. A sequential test cannot see this."""
    engine = get_engine(f"sqlite:///{tmp_path}/pending-race.db")
    Base.metadata.create_all(engine)
    Session = get_session_factory(engine)

    setup = Session()
    setup.add(Policy(id="p", name="p", type="application"))
    setup.commit()
    service = DeviceService(setup)
    raw, rt = service.create_registration_token(
        name="k", policy_id="p", expires_at=datetime.now(UTC) + timedelta(days=1)
    )
    for n in range(MAX_PENDING_PER_TOKEN - 1):
        service.enrol_device(rt_token_hash=hash_key(raw), installation_id=f"i{n}", **_META)
    rt_id = rt.id
    setup.close()

    barrier = threading.Barrier(2)
    results: list[str] = []
    lock = threading.Lock()

    def enrol(label: str) -> None:
        session = Session()
        try:
            svc = DeviceService(session)
            svc.lookup_registration_token(hash_key(raw))
            barrier.wait(timeout=10)
            outcome = svc.enrol_device(rt_token_hash=hash_key(raw), installation_id=f"race-{label}", **_META)["status"]
        except Exception as exc:
            outcome = type(exc).__name__
        finally:
            session.close()
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=enrol, args=(str(n),)) for n in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    verify = Session()
    try:
        assert results.count("Success") == 1, f"exactly one may take the last slot: {results}"
        assert verify.get(RegistrationToken, rt_id).pending_count == MAX_PENDING_PER_TOKEN
    finally:
        verify.close()


# ---------------------------------------------------------------------------
# Reaping
# ---------------------------------------------------------------------------


def test_reaping_removes_only_pending_devices_past_their_ttl(db_session):
    raw, _rt = _key(db_session)
    pre_raw, _pre_rt = _key(db_session, pre_authorized=True)
    service = DeviceService(db_session)

    stale = service.enrol_device(rt_token_hash=hash_key(raw), installation_id="stale", **_META)["result"]["device_id"]
    fresh = service.enrol_device(rt_token_hash=hash_key(raw), installation_id="fresh", **_META)["result"]["device_id"]
    active = service.enrol_device(rt_token_hash=hash_key(pre_raw), installation_id="active", **_META)["result"][
        "device_id"
    ]

    db_session.get(Device, stale).created_at = datetime.now(UTC) - timedelta(hours=73)
    db_session.commit()

    assert service.reap_pending_devices() == 1

    assert db_session.get(Device, stale) is None
    assert db_session.get(Device, fresh) is not None
    assert db_session.get(Device, active) is not None


def test_reaping_a_pending_device_leaves_no_tombstone(db_session):
    """It was never approved, so it was never told to stop.

    A tombstone here would make that installation permanently unrecoverable for
    an enrolment nobody ever acted on.
    """
    from app.db.models import DeviceTombstone

    raw, _rt = _key(db_session)
    service = DeviceService(db_session)
    device_id = service.enrol_device(rt_token_hash=hash_key(raw), installation_id="abandoned", **_META)["result"][
        "device_id"
    ]
    db_session.get(Device, device_id).created_at = datetime.now(UTC) - timedelta(hours=73)
    db_session.commit()

    service.reap_pending_devices()

    assert db_session.query(DeviceTombstone).count() == 0
    # And the installation can enrol again.
    assert (
        service.enrol_device(rt_token_hash=hash_key(raw), installation_id="abandoned", **_META)["status"] == "Success"
    )


def test_reaping_returns_the_quota_slot(db_session):
    raw, rt = _key(db_session)
    service = DeviceService(db_session)
    device_id = service.enrol_device(rt_token_hash=hash_key(raw), installation_id="x", **_META)["result"]["device_id"]
    db_session.get(Device, device_id).created_at = datetime.now(UTC) - timedelta(hours=73)
    db_session.commit()

    service.reap_pending_devices()

    db_session.expire_all()
    assert db_session.get(RegistrationToken, rt.id).pending_count == 0


def test_the_real_application_actually_installs_the_limiter():
    """The tests above build their own app, so they would all pass with the
    middleware wired to nothing. This asserts the shipped application has it,
    and that it holds the state the middleware reads."""
    from app.enrolment_rate_limit import EnrolmentRateLimitMiddleware
    from app.main import create_app

    app = create_app()

    installed = [m.cls for m in app.user_middleware]
    assert EnrolmentRateLimitMiddleware in installed, "the limiter is not installed"
    assert isinstance(app.state.enrolment_limits, EnrolmentLimits)
    assert isinstance(app.state.trusted_proxy_hops, int)


def test_the_limiter_runs_outside_authentication():
    """A flood must be refused before any credential lookup, not after one.

    Starlette applies user_middleware in reverse, so the limiter must be added
    AFTER AuthMiddleware to end up outside it.
    """
    from app.auth.middleware import AuthMiddleware
    from app.enrolment_rate_limit import EnrolmentRateLimitMiddleware
    from app.main import create_app

    installed = [m.cls for m in create_app().user_middleware]

    assert installed.index(EnrolmentRateLimitMiddleware) < installed.index(
        AuthMiddleware
    ), "the limiter runs inside auth, so a flood costs a credential lookup each"
