"""Device management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from app.auth.dependencies import require_role

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


@router.post("/enrol", status_code=201)
async def enrol_device(body: DeviceEnrolRequest, request: Request) -> dict:
    """Enrol a new device. Requires an rt_ registration token.

    Split from refresh deliberately. The combined endpoint took a registration
    token plus a client-supplied fingerprint and refreshed whatever device
    matched, which let any token holder take over any device (P0-11).
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
        )
        if result["status"] == "RegistrationTokenExhausted":
            # 403, not 401: the credential is valid and the caller is simply
            # not owed a device. Re-presenting it will never help, and 401
            # invites a client to go looking for a fresher token.
            raise HTTPException(status_code=403, detail="Registration token has no uses remaining")
        if result["status"] == "InstallationIdAlreadyEnrolled":
            # 409, not a 201 carrying a failure in the body: nothing was
            # created. The client already holds credentials for this
            # installation and should refresh, or enrol as a new one.
            raise HTTPException(status_code=409, detail="Installation ID is already enrolled")
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    finally:
        session.close()


@router.post("/{device_id}/refresh")
async def refresh_device(device_id: str, body: DeviceRefreshRequest, request: Request) -> dict:
    """Refresh a device, proving ownership with its own at_ access token."""
    token_hash = getattr(request.state, "at_token_hash", None)
    if token_hash is None:
        raise HTTPException(status_code=401, detail="Device access token required")

    session = request.app.state.session_factory()
    try:
        from app.services.device_service import DeviceService

        result = DeviceService(session).refresh_device(
            device_id=device_id,
            access_token_hash=token_hash,
            device_name=body.device_name,
            user_name=body.user_name,
            user_email=body.user_email,
            browser=body.browser,
            os=body.os,
            ext_version=body.extension_version,
            fingerprint=body.fingerprint,
        )
        if result["status"] == "InactiveDevice":
            raise HTTPException(status_code=403, detail="Device is not active")
        return result
    except PermissionError as e:
        # 403, not 401: the caller authenticated, but this credential does not
        # authorise this device.
        raise HTTPException(status_code=403, detail=str(e)) from None
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
