"""Records every non-disclosing outcome of `/v1/unredact`.

Middleware rather than a call at each exit, because the exits kept being
miscounted. Successive drafts audited one exit, then six, and each review found
another: a 422 the framework produces before any route code runs, a 403 from a
role dependency ordered ahead of the handler, a 500 propagated from a vault
whose key no longer opens it. An enumeration that grows every round is not a
mechanism, it is a tally of what has been noticed so far.

Middleware records what happened rather than what was anticipated. It cannot
miss an exit because it never asks what the exits are.

**It never changes a response.** It observes one and writes a row, and a failure
to write is a failure of the audit rather than of the request -- which is the
whole content of the split guarantee. The disclosure half lives in the route,
because withholding plaintext is a choice that exists only before the response
leaves the handler; by the time this sees a 200, the plaintext is already in it.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware

UNREDACT_PATH = "/v1/unredact"


class UnredactAuditMiddleware(BaseHTTPMiddleware):
    """Audit the attempts this route refused.

    Added BEFORE `AuthMiddleware`, which makes it the inner of the two: Starlette
    treats the last-added as outermost, so authentication runs first and
    `request.state` carries an actor by the time this sees the request.

    Authentication failures therefore stay out of scope, and for a substantive
    reason rather than convenience -- there is no authenticated actor to
    attribute them to, and naming the caller would mean recording a credential
    or its hash, which this row deliberately never carries. Those belong to an
    authentication log with its own actor model.
    """

    async def dispatch(self, request, call_next):
        if request.url.path != UNREDACT_PATH:
            return await call_next(request)

        try:
            response = await call_next(request)
        except BaseException:
            # An exception UNWINDS through here on its way to the error
            # middleware, which turns it into a 500 further out -- so waiting for
            # a response never sees it. `get_vault` deliberately propagates
            # AuthenticationFailed and UnknownKey, which is a caller presenting a
            # vault this server cannot open: exactly the case the enumeration
            # drafts kept missing, and it would have been missed again.
            self._record_refusal(request)
            raise

        # 200 is the disclosure path, recorded inside the route so it can refuse
        # when it cannot record. Recording it here as well would double-count.
        if response.status_code != 200:
            # No attempt id means the request never reached the handler -- a
            # schema rejection or a dependency refusal. The row still names the
            # caller, the action and the time, which is what an operator acts on.
            self._record_refusal(request)

        return response

    @staticmethod
    def _record_refusal(request) -> None:
        from app.services.unredact_audit import record_unredact

        request_id = getattr(request.state, "unredact_request_id", None)
        if request_id is None:
            import uuid

            request_id = f"tw_{uuid.uuid4().hex[:16]}"
        record_unredact(request, request_id, ok=False)
