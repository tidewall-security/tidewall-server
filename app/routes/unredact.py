"""POST /v1/unredact — reverse a previous redaction using the vault.

``fpe_context`` keeps its name for now despite FPE having been removed: it is
the caller-visible token that identifies a vault, and renaming it belongs with
the vault workstream rather than a deletion.
"""

from __future__ import annotations

import base64
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.dependencies import deny_device_credentials, require_role
from app.models import UnredactRequest, UnredactResponse, UnredactResult
from app.utils import now_iso as _now_iso

router = APIRouter()


@router.post(
    "/v1/unredact",
    response_model=UnredactResponse,
    # `api` alone is not enough here: every enrolled device holds that role,
    # so this endpoint was reachable by any laptop in the fleet — and it
    # resolves a caller-supplied vault id with no ownership check, because
    # `Vault` has no owner column to check against. Reversing a redaction is
    # denied to device credentials until vaults are owned.
    dependencies=[Depends(require_role("api")), Depends(deny_device_credentials)],
)
async def unredact(body: UnredactRequest, request: Request) -> UnredactResponse:
    # Decode fpe_context to determine type
    try:
        ctx_json = json.loads(base64.b64decode(body.fpe_context))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid fpe_context") from None

    request_time = _now_iso()
    request_id = f"tw_{uuid.uuid4().hex[:16]}"

    # The FPE branch accepted a caller-supplied algorithm, tweak and radix and
    # decrypted under a single global key — an unauthenticated decryption
    # oracle for a construction that was withdrawn from NIST SP 800-38G.
    # Removed with the rest of FPE.

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
