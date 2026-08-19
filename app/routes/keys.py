"""API key management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth.dependencies import require_role
from app.auth.grants import GrantError

router = APIRouter(prefix="/v1/keys", tags=["keys"])


class CreateKeyRequest(BaseModel):
    name: str
    role: str = "api"
    policy_id: str | None = None
    collector_type: str | None = None
    # Content grants, orthogonal to the role rather than implied by it. Only a
    # viewer or admin bound to a policy may hold one; KeyService validates.
    grants: list[str] | None = None


def _key_to_dict(api_key) -> dict:
    return {
        "id": api_key.id,
        "name": api_key.name,
        "key_prefix": api_key.key_prefix,
        "role": api_key.role,
        "policy_id": api_key.policy_id,
        "collector_type": api_key.collector_type,
        # Exactly what is persisted. The implication that a full-content grant
        # permits the matches view is applied at read time and never
        # materialised here -- otherwise it would look like a third grant and
        # later export checks could inherit it by accident.
        "grants": list(api_key.grants or []),
        "created_at": str(api_key.created_at),
        "expires_at": str(api_key.expires_at) if api_key.expires_at else None,
    }


@router.get("", dependencies=[Depends(require_role("admin"))])
async def list_keys(request: Request) -> list[dict]:
    session = request.app.state.session_factory()
    try:
        from app.services.key_service import KeyService

        svc = KeyService(session)
        return [_key_to_dict(k) for k in svc.list_keys()]
    finally:
        session.close()


@router.post("", status_code=201, dependencies=[Depends(require_role("admin"))])
async def create_key(body: CreateKeyRequest, request: Request) -> dict:
    session = request.app.state.session_factory()
    try:
        from app.services.key_service import KeyService

        svc = KeyService(session)
        raw_key, api_key = svc.create_key(
            name=body.name,
            role=body.role,
            policy_id=body.policy_id,
            collector_type=body.collector_type,
            grants=body.grants,
        )
        result = _key_to_dict(api_key)
        result["key"] = raw_key  # Returned ONCE, never stored
        return result
    except (GrantError, ValueError) as e:
        # Only the expected validation failures. A blanket `except Exception`
        # turned a database fault into a 400 carrying exception text; those are
        # now 500s with a fixed body.
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@router.delete("/{key_id}", status_code=204, dependencies=[Depends(require_role("admin"))])
async def delete_key(key_id: str, request: Request) -> None:
    session = request.app.state.session_factory()
    try:
        from app.services.key_service import KeyService

        svc = KeyService(session)
        svc.delete_key(key_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        session.close()
