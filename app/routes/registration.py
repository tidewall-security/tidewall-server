"""Registration token management endpoints."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth.dependencies import require_role

router = APIRouter(prefix="/v1/registration-tokens", tags=["registration-tokens"])


class CreateRegistrationTokenRequest(BaseModel):
    name: str
    # Required: every device enrolled with this token inherits it as its scope.
    # Making it optional is what left the column unwritten by anything, so the
    # inheritance code at enrolment read NULL and every device fell back to the
    # default policy.
    policy_id: str
    # Required, and capped by the service. A key with no deadline is a
    # permanent capability to create devices; the only containment for a leaked
    # one is then that somebody eventually notices.
    expires_at: datetime
    # None means uncapped, which is legitimate for a fleet key whose expiry is
    # doing the bounding.
    max_uses: int | None = None
    # False by default. True makes the key sufficient on its own to produce a
    # working device, which is what fleet deployment needs and what makes a leak
    # of such a key immediately material.
    pre_authorized: bool = False


def _to_dict(rt) -> dict:
    return {
        "id": rt.id,
        "name": rt.name,
        "token_prefix": rt.token_prefix,
        "policy_id": rt.policy_id,
        "created_by": rt.created_by,
        "created_at": str(rt.created_at),
        "expires_at": str(rt.expires_at),
        "max_uses": rt.max_uses,
        "uses": rt.uses,
        "pre_authorized": rt.pre_authorized,
    }


@router.post("", status_code=201, dependencies=[Depends(require_role("admin"))])
async def create_registration_token(body: CreateRegistrationTokenRequest, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.services.device_service import DeviceService

        svc = DeviceService(session)
        raw_token, record = svc.create_registration_token(
            name=body.name,
            policy_id=body.policy_id,
            created_by=getattr(request.state, "api_key_id", None),
            expires_at=body.expires_at,
            max_uses=body.max_uses,
            pre_authorized=body.pre_authorized,
        )
        result = _to_dict(record)
        result["token"] = raw_token  # Returned ONCE, never stored
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@router.get("", dependencies=[Depends(require_role("admin"))])
async def list_registration_tokens(request: Request) -> list[dict]:
    session = request.app.state.session_factory()
    try:
        from app.services.device_service import DeviceService

        svc = DeviceService(session)
        return [_to_dict(rt) for rt in svc.list_registration_tokens()]
    finally:
        session.close()


@router.delete("/{token_id}", status_code=204, dependencies=[Depends(require_role("admin"))])
async def delete_registration_token(token_id: str, request: Request) -> None:
    session = request.app.state.session_factory()
    try:
        from app.services.device_service import DeviceService

        svc = DeviceService(session)
        svc.delete_registration_token(token_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        session.close()
