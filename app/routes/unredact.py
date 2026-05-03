"""POST /v1/unredact — reverse a previous redaction using the vault or FPE."""

from __future__ import annotations

import base64
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.dependencies import require_role
from app.models import UnredactRequest, UnredactResponse, UnredactResult
from app.utils import now_iso as _now_iso

router = APIRouter()


@router.post(
    "/v1/unredact",
    response_model=UnredactResponse,
    dependencies=[Depends(require_role("api"))],
)
async def unredact(body: UnredactRequest, request: Request) -> UnredactResponse:
    # Decode fpe_context to determine type
    try:
        ctx_json = json.loads(base64.b64decode(body.fpe_context))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid fpe_context")

    request_time = _now_iso()
    request_id = f"tw_{uuid.uuid4().hex[:16]}"

    # FPE-based unredaction
    if "algorithm" in ctx_json:
        session = request.app.state.session_factory()
        try:
            from app.services.fpe_service import FPEService

            fpe = FPEService(session)
            restored = fpe.decrypt(str(body.redacted_data), body.fpe_context)
            return UnredactResponse(
                request_id=request_id,
                request_time=request_time,
                response_time=_now_iso(),
                status="Success",
                summary="Unredacted via FPE",
                result=UnredactResult(data=restored),
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"FPE decryption failed: {e}")
        finally:
            session.close()

    # Vault-based unredaction (TidewallVault dict lookup)
    vault_mgr = request.app.state.vault_manager
    vault_id = ctx_json.get("vault_id")
    if not vault_id:
        raise HTTPException(status_code=400, detail="Invalid fpe_context: no vault_id or algorithm")

    vault = vault_mgr.get_vault(vault_id)
    if not vault:
        raise HTTPException(status_code=404, detail="Vault expired or not found")

    restored = vault.unredact(str(body.redacted_data))
    return UnredactResponse(
        request_id=request_id,
        request_time=request_time,
        response_time=_now_iso(),
        status="Success",
        summary="Unredacted via vault",
        result=UnredactResult(data=restored),
    )
