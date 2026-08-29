"""Validation errors that do not quote the request back.

FastAPI's default handler for :class:`RequestValidationError` puts the offending
value in the response as ``input``::

    {"detail": [{"type": "dict_type", "loc": ["body", "guard_input"],
                 "msg": "Input should be a valid dictionary",
                 "input": "my-ssn-is-123-45-6789"}]}

For most services that is a convenience. For this one it inverts the product:
the whole purpose is to stop sensitive text reaching places it should not, and
the error path hands it straight back.

The caller supplied the value, so this is not disclosure to a new party -- but a
response body travels much further than the request did. ``app/routes/guard.py``
already records the same reasoning for its own payload: proxies, APM tools,
browser devtools and the caller's own logging all see a response. A prompt
rejected for its *shape* is exactly as sensitive as one accepted, and rather
more likely to end up in an error tracker.

``loc``, ``type`` and ``msg`` are kept. They say which field was wrong and why,
which is everything a caller needs to fix the request, and none of it is the
value. ``ctx`` is dropped wholesale: it is a free-form dict whose contents vary
by validator and can contain the input, so allowing it through would mean
auditing every validator pydantic ships and every one it adds later.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

#: Kept from each error. Anything not named here is dropped, so a new pydantic
#: field arrives redacted rather than disclosed -- the safe direction for a
#: structure this code does not control.
_SAFE_FIELDS = ("type", "loc", "msg")


async def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    """422 with the shape of the error and none of its content."""
    detail = [{field: error[field] for field in _SAFE_FIELDS if field in error} for error in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": detail})


def install(app) -> None:
    """Register the handler. One call site for production and tests alike.

    A test that wires its own handler proves the handler and not the wiring, and
    the wiring is half the defect: this was missing everywhere, not wrong
    somewhere.
    """
    app.add_exception_handler(RequestValidationError, validation_error_handler)
