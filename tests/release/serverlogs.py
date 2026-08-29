"""Server logs, captured BY THEIR OWN SELECTORS.

`uvicorn.access`, `uvicorn.error` and stderr are three different sinks with
three different failure modes, and capturing "the logs" collapses them:

  * a handler attached to the ROOT logger catches records that propagate, and
    misses any logger with `propagate = False` -- which uvicorn's loggers are
    routinely configured with;
  * `caplog` captures logging records and never sees a direct write to
    stderr, so a traceback printed by the interpreter is invisible;
  * counting access records without correlating them to exchanges reports a
    number that looks right and is not: one request that logs twice, or a
    health check nobody counted, moves it.

So each sink is captured by its own selector, access records are correlated to
the exchange that produced them, and an ERROR PRODUCER WITNESS proves the
error sink would have caught something if there had been anything to catch.
"""

from __future__ import annotations

import io
import logging
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field

#: The three sinks, each named by the selector that reaches it.
ACCESS_LOGGER = "uvicorn.access"
ERROR_LOGGER = "uvicorn.error"
STDERR = "<stderr>"


class SinkNotObserved(Exception):
    """A producer control's own record was not captured."""


@dataclass
class LogCapture:
    """Records per sink, kept apart."""

    records: dict[str, list[str]] = field(default_factory=dict)

    def add(self, sink: str, message: str) -> None:
        self.records.setdefault(sink, []).append(message)

    def of(self, sink: str) -> list[str]:
        return self.records.get(sink, [])

    def carrying(self, sink: str, needle: str) -> list[str]:
        return [m for m in self.of(sink) if needle in m]

    def verify_producer(self, sink: str, sentinel: str) -> None:
        if not self.carrying(sink, sentinel):
            raise SinkNotObserved(
                f"the producer control's own record did not reach {sink}, so an "
                f"absence of {sink} records proves nothing"
            )


class _Handler(logging.Handler):
    def __init__(self, capture: LogCapture, sink: str) -> None:
        super().__init__()
        self._capture = capture
        self._sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        self._capture.add(self._sink, record.getMessage())


@contextmanager
def capturing_server_logs():
    """Attach to each named logger DIRECTLY, and replace stderr.

    Attaching to the named logger rather than the root is what survives
    `propagate = False`; replacing `sys.stderr` is what catches a write that
    never went through logging at all.
    """
    capture = LogCapture()
    attached = []

    for sink in (ACCESS_LOGGER, ERROR_LOGGER):
        logger = logging.getLogger(sink)
        handler = _Handler(capture, sink)
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        previous_level = logger.level
        logger.setLevel(logging.DEBUG)
        attached.append((logger, handler, previous_level))

    original_stderr = sys.stderr
    buffer = io.StringIO()
    sys.stderr = buffer
    try:
        yield capture
    finally:
        sys.stderr = original_stderr
        for line in buffer.getvalue().splitlines():
            if line.strip():
                capture.add(STDERR, line)
        for logger, handler, previous_level in attached:
            logger.removeHandler(handler)
            logger.setLevel(previous_level)


def access_records_for(capture: LogCapture, exchange_id: str) -> list[str]:
    """Access records CORRELATED to one exchange.

    A bare count over the sink includes every other request the process
    handled, and reads entirely plausible while doing so.
    """
    return capture.carrying(ACCESS_LOGGER, exchange_id)
