"""Logging at a boundary where the exception may contain the prompt.

`exc_info=True` writes the traceback, and a traceback carries the arguments of
every frame in it. At scan time those arguments are the text being scanned, so
a tokenizer or model that raises on a malformed input can put that input into
the operator's log — a copy of the content the product exists to contain,
written to a place nobody thinks of as a content store, by a path that only
opens when something has already gone wrong.

Third-party libraries make this worse rather than better: their exception
messages routinely quote the offending value, so even the message alone can
carry it without any traceback at all.

`describe()` returns what an operator actually needs to act — the exception
type and, where a library provides one, a short stable reason — and nothing
that came out of the request.

This is deliberately not applied to model *load* failures. Those exceptions
carry a model path and no request content, and the traceback is genuinely the
most useful thing in the log when a model will not load.
"""

from __future__ import annotations

_MAX_REASON_LENGTH = 200


def describe(exc: BaseException) -> str:
    """A log-safe description of a scan-time failure.

    Deliberately drops the message. Distinguishing a truncation-safe library
    message from one quoting the input is not something this can decide per
    exception, and the type plus the call site is what identifies the fault.
    """
    return type(exc).__name__


def describe_with_reason(exc: BaseException, reason: str) -> str:
    """Type plus a caller-supplied reason that is known not to be derived
    from request content."""
    trimmed = reason[:_MAX_REASON_LENGTH]
    return f"{type(exc).__name__}: {trimmed}"
