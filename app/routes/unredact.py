"""POST /v1/unredact — reverse a previous redaction using the vault.

``fpe_context`` keeps its name for now despite FPE having been removed: it is
the caller-visible token that identifies a vault, and renaming it belongs with
the vault workstream rather than a deletion.
"""

from __future__ import annotations

import base64
import json
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.dependencies import deny_device_credentials, require_role
from app.models import UnredactRequest, UnredactResponse, UnredactResult
from app.utils import now_iso as _now_iso

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/v1/unredact",
    response_model=UnredactResponse,
    # `api` alone is not enough here: every enrolled device holds that role,
    # so this endpoint was reachable by any laptop in the fleet. Vaults are now
    # owned, and this denial stays regardless: no browser client reverses a
    # redaction. A device token is the most exposed credential in the system,
    # and handing recovered PII back into a page is not something a policy
    # binding should be able to authorise.
    dependencies=[Depends(require_role("api")), Depends(deny_device_credentials)],
)
async def unredact(body: UnredactRequest, request: Request) -> UnredactResponse:
    # Minted BEFORE the first exit, and published on request.state so the audit
    # middleware records the SAME attempt this handler is serving rather than a
    # second identifier for it. It used to be minted after the base64 decode, so
    # a malformed context had no attempt id at all.
    request_id = f"tw_{uuid.uuid4().hex[:16]}"
    # Published so the middleware records the SAME attempt this handler is
    # serving. Deleting this line breaks no test and cannot: a refusal response
    # carries no request id, so whether the two agree is not observable through
    # the API, and the middleware mints its own when the state is absent.
    #
    # Kept because one attempt should have one identifier the moment that
    # becomes visible -- if the id is ever added to an error body or an
    # application log, two ids for one request is a correlation bug that would
    # have to be found rather than avoided.
    request.state.unredact_request_id = request_id
    request_time = _now_iso()

    try:
        ctx_json = json.loads(base64.b64decode(body.fpe_context))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid fpe_context") from None

    # The FPE branch accepted a caller-supplied algorithm, tweak and radix and
    # decrypted under a single global key — an unauthenticated decryption
    # oracle for a construction that was withdrawn from NIST SP 800-38G.
    # Removed with the rest of FPE.

    vault_mgr = request.app.state.vault_manager
    vault_id = ctx_json.get("vault_id")
    if not vault_id:
        raise HTTPException(status_code=400, detail="Invalid fpe_context: no vault_id or algorithm")

    # The caller's BOUND policy, never a resolved default. An unbound key owns
    # nothing, so it can reverse nothing -- and it is refused with the same 404
    # a missing vault gets, because a caller able to tell "not yours" from "no
    # such vault" can enumerate other policies' ids.
    caller_policy = getattr(request.state, "policy_id", None)
    if not caller_policy:
        raise HTTPException(status_code=404, detail="Vault expired or not found")

    vault = vault_mgr.get_vault(vault_id, caller_policy)
    if not vault:
        raise HTTPException(status_code=404, detail="Vault expired or not found")

    if vault.is_empty:
        # The row exists and holds no mapping, so unredact() would replace
        # nothing and hand the caller back the text it sent -- previously with
        # status="Success" and summary="Unredacted via vault". A vault id only
        # exists because a redaction produced one, so this is lost data, not an
        # empty result.
        #
        # 500 rather than 404: the vault was found. This is the server failing
        # to keep what it promised to keep, and it should be loud. The guard
        # route no longer issues a token for a mapping it did not store, so
        # reaching here means a row written by an older build or one emptied
        # since.
        logger.error(
            "vault %s holds no mapping; refusing to report a reversal that did not happen",
            vault_id,
        )
        raise HTTPException(
            status_code=500,
            detail="Vault holds no redaction mapping; the original data cannot be recovered",
        )

    submitted = str(body.redacted_data)
    restored = vault.unredact(submitted)

    # DISCLOSED, not merely "returned 200". `unredact` replaces the placeholders
    # it finds and returns the text unchanged when it finds none -- a caller can
    # hold a valid vault id and submit text containing none of its placeholders,
    # and that request succeeds having revealed nothing. Recording it as a
    # reversal would attest to a plaintext recovery that did not happen, and an
    # audit trail that overstates is worse than one that is merely incomplete.
    disclosed = restored != submitted

    # A disclosure is recorded before it leaves, or it does not leave. The
    # plaintext exists here and has NOT yet reached the caller, which is the only
    # moment this choice is available -- middleware sees the response with the
    # data already in it. The vault outlives this request, so a caller who
    # retries after the database recovers gets their data.
    #
    # When nothing was disclosed the record is best-effort, like any other
    # outcome that revealed nothing: refusing here would deny a caller a response
    # that gave them nothing anyway.
    from app.services.unredact_audit import record_unredact

    if not record_unredact(request, request_id, ok=disclosed) and disclosed:
        raise HTTPException(
            status_code=500,
            detail="the reversal could not be recorded, so it was not completed",
        )

    return UnredactResponse(
        request_id=request_id,
        request_time=request_time,
        response_time=_now_iso(),
        status="Success",
        summary="Unredacted via vault",
        result=UnredactResult(data=restored),
    )
