"""Registration token management endpoints."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth.dependencies import require_role

router = APIRouter(prefix="/v1/registration-tokens", tags=["registration-tokens"])


class CreateRegistrationTokenRequest(BaseModel):
    name: str
    expires_at: datetime | None = None


def _to_dict(rt) -> dict:
    return {
        "id": rt.id,
        "name": rt.name,
        "token_prefix": rt.token_prefix,
        "created_by": rt.created_by,
        "created_at": str(rt.created_at),
        "expires_at": str(rt.expires_at) if rt.expires_at else None,
    }


@router.post("", status_code=201, dependencies=[Depends(require_role("admin"))])
async def create_registration_token(body: CreateRegistrationTokenRequest, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.services.device_service import DeviceService

        svc = DeviceService(session)
        raw_token, record = svc.create_registration_token(
            name=body.name,
            created_by=getattr(request.state, "api_key_id", None),
            expires_at=body.expires_at,
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
