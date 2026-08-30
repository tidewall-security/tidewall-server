"""Recording that someone tried to reverse a redaction.

`/v1/unredact` is the one endpoint that turns redacted data back into the
plaintext this product exists to keep out of the wrong places. That it happened,
and who asked, is worth a durable record.

**The guarantee is split by whether anything was disclosed.** A reversal that
discloses data is recorded or it does not happen; an attempt that reaches the
application and discloses nothing is recorded on a best-effort basis, and a
failure to record one is itself logged at error.

The absolute form -- "every reversal, succeeded or refused, writes a row" --
cannot be honoured. `ActivityService.log` commits, on a database that admits one
writer and has several other committers, so the write can fail. A guarantee
about recording and a guarantee about serving cannot both be unconditional when
they share a failure. The two halves differ in what is at stake: an unrecorded
success means plaintext left the building with nothing attesting to it, and at
the moment the log fails that plaintext has *not yet left the process*, so
refusing is still available. An unrecorded refusal means someone probed and it
went unnoted; the caller received nothing, and turning their 400 into a 500
because the log is down helps no one.

**A row names the caller and never the vault.** Not its id, not a hash of it,
not its owning policy, on either outcome. `/v1/activity` is admin-role and
globally unfiltered, and admin outranks api, so one credential can both probe
this endpoint and read every record. A hash does not help -- the prober supplied
the id and can hash its own candidate. Recording the *probed* vault's owner is
worst of all: it converts a uniform 404 into a definitive statement that the id
exists and names who holds it. Caller attributes are safe because they describe
someone who already knows them; target attributes are not.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

#: Written when no credential kind is recognised. Reaching it means the
#: middleware ran for a request the authentication layer did not classify, which
#: is a defect rather than a caller.
UNKNOWN_ACTOR = ("unknown", "unknown")


def actor_for(state: Any) -> tuple[str, str]:
    """The caller, as a kind and an id.

    A pair rather than a bare string so a credential type added later is a
    visible gap here instead of a silent `"unknown"`. `api_key_id` is None for a
    device -- the middleware sets `device_id` instead -- so a helper reading only
    the former attributed every device attempt to nobody.

    Only these two can reach an audit point on this route. A `dr_` or `rt_` token
    is refused by the authentication middleware before any route code runs.
    """
    device_id = getattr(state, "device_id", None)
    if device_id is not None:
        return ("device", str(device_id))
    api_key_id = getattr(state, "api_key_id", None)
    if api_key_id is not None:
        return ("api_key", str(api_key_id))
    return UNKNOWN_ACTOR


def record_unredact(request: Any, request_id: str, *, ok: bool) -> bool:
    """Record one reversal attempt. True if it was durably recorded.

    Never raises. The refusal path has already decided the caller gets nothing
    and must still return the status it earned; only the success path reads the
    return value, because a disclosure that cannot be recorded must not happen.
    """
    kind, actor_id = actor_for(request.state)
    session = None
    try:
        session = request.app.state.session_factory()
        from app.services.activity_service import ActivityService

        ActivityService(session).log(
            actor=f"{kind}:{actor_id}",
            action="unredact" if ok else "unredact_refused",
            target_type="vault",
            # The ATTEMPT, never the vault. This route mints its own request id,
            # and it identifies the caller's own request rather than anything
            # they were asking about.
            target_id=request_id,
            new_value={"policy_id": getattr(request.state, "policy_id", None)},
        )
        return True
    except Exception:
        logger.exception("failed to record an unredact attempt")
        return False
    finally:
        if session is not None:
            session.close()
