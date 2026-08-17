"""Device management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth.dependencies import require_role

router = APIRouter(prefix="/v1/devices", tags=["devices"])


class DeviceEnrolRequest(BaseModel):
    # Client-generated, high-entropy, stored by the extension. This is the
    # device's identity; `fingerprint` is advisory metadata only.
    installation_id: str
    device_name: str
    user_name: str
    user_email: str
    browser: str = ""
    os: str = ""
    extension_version: str = ""
    fingerprint: str | None = None


class DeviceRefreshRequest(BaseModel):
    device_name: str | None = None
    user_name: str | None = None
    user_email: str | None = None
    browser: str | None = None
    os: str | None = None
    extension_version: str | None = None
    fingerprint: str | None = None


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

        return DeviceService(session).enrol_device(
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

        return DeviceService(session).refresh_device(
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
    except PermissionError as e:
        # 403, not 401: the caller authenticated, but this credential does not
        # authorise this device.
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
