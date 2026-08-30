"""Device management endpoints."""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

from app.auth.dependencies import require_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/devices", tags=["devices"])

_UUID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
_NIL_UUID = "00000000-0000-0000-0000-000000000000"


class DeviceEnrolRequest(BaseModel):
    # Client-generated, stored by the extension. This is the device's identity;
    # `fingerprint` is advisory metadata only.
    #
    # This checks the *form* — a UUID, as produced by `crypto.randomUUID()` —
    # and nothing more. It cannot establish that the value is random: the
    # server sees only the result, so a client that derives its ID predictably
    # produces something indistinguishable from a good one. Requiring the shape
    # rules out the obviously weak values a free-text field allowed ("", "1",
    # a username) and gives the client an unambiguous contract; generating it
    # from a CSPRNG is the client's responsibility.
    #
    # It matters because enrolment is first-claim and never reassigns: anyone
    # holding a registration token who can predict an installation ID can
    # enrol it first and deny the genuine client. That residual risk belongs to
    # the client's generator, and is not something this check removes.
    installation_id: str = Field(pattern=_UUID_PATTERN)
    device_name: str
    user_name: str
    user_email: str
    browser: str = ""
    os: str = ""
    extension_version: str = ""
    fingerprint: str | None = None

    @field_validator("installation_id")
    @classmethod
    def _reject_nil_uuid(cls, value: str) -> str:
        # The one constant value a broken generator reliably produces.
        if value.lower() == _NIL_UUID:
            raise ValueError("installation_id must not be the nil UUID")
        return value

    # Supplied only when recovering a tombstoned installation. Delivered out of
    # band by an administrator; a wrong value answers exactly as none does.
    recovery_secret: str | None = None


class DeviceRefreshRequest(BaseModel):
    device_name: str | None = None
    user_name: str | None = None
    user_email: str | None = None
    browser: str | None = None
    os: str | None = None
    extension_version: str | None = None
    fingerprint: str | None = None


class ApproveDeviceRequest(BaseModel):
    confirmation_code: str


class UpdateDeviceStatusRequest(BaseModel):
    status: str


#: The taxonomy's HTTP projection. device_pending is 202, not an error: the
#: request was understood and the client should poll with backoff. Everything
#: else is a refusal, and device_revoked is 403 because re-presenting the
#: credential will never help.
#: Enrolment outcomes that created nothing. Every one of these used to fall
#: through the 201 route and answer "Created" with a null result, so a client
#: keying on the status code would store an empty credential tuple and wedge.
#: Two of them were added later than the route's mapping and simply never got
#: an entry -- which is why this is a table rather than a chain of ifs: a status
#: with no entry now fails loudly instead of silently succeeding.
_ENROL_FAILURE_STATUS = {
    "RegistrationTokenExhausted": 403,
    "InstallationIdAlreadyEnrolled": 409,
    # Valid credential, but this installation may not enrol. Re-presenting it
    # will not help; an administrator must authorise recovery out of band.
    "InstallationTombstoned": 403,
    # Capacity, not misbehaviour: the quota frees as devices are approved or
    # reaped. 429 tells the client to come back rather than to give up.
    "PendingQuotaExceeded": 429,
}


#: The enrolment table above learned this the expensive way; this one is its
#: sibling and had none of the same protection. It is pinned to the service by
#: a test, an unmapped outcome is handled deliberately rather than by KeyError,
#: and "InactiveDevice" is gone -- nothing produced it, no test named it, and
#: no client had heard of it. A dead row is a claim that an outcome exists.
_REFRESH_FAILURE_STATUS = {
    "device_revoked": 403,
    "credential_unknown": 401,
    "credential_expired": 401,
    "device_pending": 202,
}


#: The taxonomy the clients key on, declared so it reaches the generated
#: OpenAPI document. Before this, both routes were annotated `-> dict` and set
#: their status code on the injected Response, so the schema recorded only the
#: declared success code: an extension asserting against the schema could see
#: that /enrol exists and what it accepts, and nothing at all about the four
#: ways it refuses. A client keys on `reason`, never on the status alone --
#: 401 covers two refresh outcomes that call for different behaviour, and 202
#: is not an error -- so `reason` is the field that had to become expressible.
EnrolFailureReason = Literal[
    "RegistrationTokenExhausted",
    "InstallationIdAlreadyEnrolled",
    "InstallationTombstoned",
    "PendingQuotaExceeded",
]

RefreshFailureReason = Literal[
    "device_revoked",
    "credential_unknown",
    "credential_expired",
    "device_pending",
]


class EnrolFailure(BaseModel):
    """`status` and `reason` carry the same value; both are declared.

    The duplication is in the wire format already. Typing only one of them
    would put half the taxonomy in the schema and leave a reader guessing
    whether the other field is free-form.
    """

    status: EnrolFailureReason
    reason: EnrolFailureReason
    result: None = None


class RefreshFailure(BaseModel):
    status: RefreshFailureReason
    reason: RefreshFailureReason
    result: None = None


#: DERIVED from the tables, never written out. A hand-written responses dict is
#: a fourth place to update when an outcome is added, and this module's whole
#: history is places that did not get updated.
_ENROL_FAILURE_RESPONSES: dict[int | str, dict] = {
    code: {"model": EnrolFailure} for code in sorted(set(_ENROL_FAILURE_STATUS.values()))
}

_REFRESH_FAILURE_RESPONSES: dict[int | str, dict] = {
    code: {"model": RefreshFailure} for code in sorted(set(_REFRESH_FAILURE_STATUS.values()))
}


def _device_to_dict(device) -> dict:
    return {
        "id": device.id,
        "installation_id": device.installation_id,
        "fingerprint": device.fingerprint,
        "device_name": device.device_name,
        "user_name": device.user_name,
        "user_email": device.user_email,
        "browser": device.browser,
        "os": device.os,
        "ext_version": device.ext_version,
        "reg_token_id": device.reg_token_id,
        "policy_id": device.policy_id,
        "status": device.status,
        # NO confirmation_code. This listing is readable by `viewer`, and the
        # code is the one field an approver holds that a claimant cannot supply.
        # Publishing it here collapses approval back to "device id alone".
        "last_seen": str(device.last_seen),
        "created_at": str(device.created_at),
    }


@router.post("/enrol", status_code=201, responses=_ENROL_FAILURE_RESPONSES)
async def enrol_device(body: DeviceEnrolRequest, request: Request, response: Response) -> dict:
    """Enrol a new device. Requires an rt_ registration token.

    Split from refresh deliberately. The combined endpoint took a registration
    token plus a client-supplied fingerprint and refreshed whatever device
    matched, which let any token holder take over any device.
    """
    rt_token_hash = getattr(request.state, "rt_token_hash", None)
    if rt_token_hash is None:
        raise HTTPException(status_code=401, detail="Registration token required")

    session = request.app.state.session_factory()
    try:
        from app.services.device_service import DeviceService

        result = DeviceService(session).enrol_device(
            rt_token_hash=rt_token_hash,
            installation_id=body.installation_id,
            device_name=body.device_name,
            user_name=body.user_name,
            user_email=body.user_email,
            browser=body.browser,
            os=body.os,
            ext_version=body.extension_version,
            fingerprint=body.fingerprint,
            recovery_secret=body.recovery_secret,
        )
        if result["status"] != "Success":
            status_code = _ENROL_FAILURE_STATUS.get(result["status"])
            if status_code is None:
                # An outcome nobody mapped. 500 rather than 201: answering
                # "Created" for something we do not understand is exactly how
                # the two statuses above came to be silently successful.
                logger.error("Unmapped enrolment outcome %r", result["status"])
                raise HTTPException(status_code=500, detail="Unhandled enrolment outcome")
            response.status_code = status_code
            return {"status": result["status"], "reason": result["status"], "result": None}

        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    finally:
        session.close()


@router.post("/{device_id}/refresh", responses=_REFRESH_FAILURE_RESPONSES)
async def refresh_device(device_id: str, body: DeviceRefreshRequest, request: Request, response: Response) -> dict:
    """Refresh a device, proving ownership with its own dr_ refresh token.

    A clean cut: the at_ access token was the credential here and is now
    refused. Accepting both would leave the one-hour lockout in place for any
    client that kept using the old one, which is the entire problem this
    replaces.
    """
    token_hash = getattr(request.state, "dr_token_hash", None)
    if token_hash is None:
        raise HTTPException(status_code=401, detail="Device refresh token required")

    session = request.app.state.session_factory()
    try:
        from app.services.device_service import DeviceService

        result = DeviceService(session).refresh_device(
            device_id=device_id,
            refresh_token_hash=token_hash,
            device_name=body.device_name,
            user_name=body.user_name,
            user_email=body.user_email,
            browser=body.browser,
            os=body.os,
            ext_version=body.extension_version,
            fingerprint=body.fingerprint,
        )
        if result["status"] == "ok":
            return result

        # The body always carries the machine-readable reason. A client keys on
        # THAT, never on the status code alone: 401 covers two outcomes that
        # call for different behaviour, and 202 is not an error at all.
        # Set on the injected Response rather than returning a JSONResponse: a
        # `dict | JSONResponse` return annotation makes FastAPI try to build a
        # Pydantic response model from the union and fail at import time,
        # taking every route in this module with it.
        status_code = _REFRESH_FAILURE_STATUS.get(result["status"])
        if status_code is None:
            # Matching the enrolment route. A bare KeyError here would also end
            # as a 500, so the disposition is the same -- but it arrives as an
            # unhandled exception with no line naming the outcome, and it reads
            # to the next person as a crash rather than as a case nobody mapped.
            logger.error("Unmapped refresh outcome %r", result["status"])
            raise HTTPException(status_code=500, detail="Unhandled refresh outcome")
        response.status_code = status_code
        return {"status": result["status"], "reason": result["status"], "result": None}
    finally:
        session.close()


@router.post("/{device_id}/approve", dependencies=[Depends(require_role("admin"))])
async def approve_device(device_id: str, body: ApproveDeviceRequest, request: Request) -> dict:
    """Activate a pending device by matching the code it displayed."""
    session = request.app.state.session_factory()
    try:
        from app.services.device_service import DeviceService

        device = DeviceService(session).approve_device(device_id=device_id, confirmation_code=body.confirmation_code)
        return _device_to_dict(device)
    except LookupError:
        raise HTTPException(status_code=404, detail="Device not found") from None
    except PermissionError as e:
        # 403: the caller authenticated and is an admin; the code did not match,
        # or the device was not awaiting approval.
        raise HTTPException(status_code=403, detail=str(e)) from None
    finally:
        session.close()


@router.post("/{device_id}/authorise-recovery", dependencies=[Depends(require_role("admin"))])
async def authorise_device_recovery(device_id: str, request: Request) -> dict:
    """Grant one recovery for a tombstoned device. Returns the secret ONCE.

    The secret is delivered out of band to the person who should get the device
    back, and consumed atomically with the replacement enrolment. Re-enable
    authorises a consumer, not merely a race: a bare "this installation may
    enrol again" flag is claimable by whoever asks first, including the party
    the revocation was aimed at.
    """
    session = request.app.state.session_factory()
    try:
        from app.services.device_service import DeviceService

        secret = DeviceService(session).authorise_recovery(device_id)
        # Returned once and never stored in the clear, like every other
        # credential this service mints.
        return {"device_id": device_id, "recovery_secret": secret}
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e)) from None
    except PermissionError as e:
        raise HTTPException(status_code=409, detail=str(e)) from None
    finally:
        session.close()


@router.get("", dependencies=[Depends(require_role("viewer"))])
async def list_devices(request: Request) -> list[dict]:
    session = request.app.state.session_factory()
    try:
        from app.services.device_service import DeviceService

        svc = DeviceService(session)
        return [_device_to_dict(d) for d in svc.list_devices()]
    finally:
        session.close()


@router.patch("/{device_id}", dependencies=[Depends(require_role("admin"))])
async def update_device_status(device_id: str, body: UpdateDeviceStatusRequest, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.services.device_service import DeviceService

        svc = DeviceService(session)
        device = svc.update_device_status(device_id, body.status)
        return _device_to_dict(device)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        session.close()


@router.delete("/{device_id}", status_code=204, dependencies=[Depends(require_role("admin"))])
async def delete_device(device_id: str, request: Request) -> None:
    session = request.app.state.session_factory()
    try:
        from app.services.device_service import DeviceService

        svc = DeviceService(session)
        svc.delete_device(device_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        session.close()
