"""Each sink by its own selector, and the failure modes of not doing that."""

from __future__ import annotations

import logging
import sys

import pytest

from tests.release.serverlogs import (
    ACCESS_LOGGER,
    ERROR_LOGGER,
    STDERR,
    LogCapture,
    SinkNotObserved,
    access_records_for,
    capturing_server_logs,
)

CANARY = "CANARY-LOG-9e04"


def test_each_sink_is_captured_separately():
    with capturing_server_logs() as capture:
        logging.getLogger(ACCESS_LOGGER).info("access %s", CANARY)
        logging.getLogger(ERROR_LOGGER).error("error %s", CANARY)
        print(f"stderr {CANARY}", file=sys.stderr)

    assert capture.carrying(ACCESS_LOGGER, CANARY)
    assert capture.carrying(ERROR_LOGGER, CANARY)
    assert capture.carrying(STDERR, CANARY)


def test_a_sink_with_propagate_disabled_is_still_captured():
    """The failure mode of attaching to the root logger.

    uvicorn's loggers are routinely configured with propagate = False, and a
    root handler then sees nothing while reporting a clean run.
    """
    logger = logging.getLogger(ACCESS_LOGGER)
    previous = logger.propagate
    logger.propagate = False
    try:
        with capturing_server_logs() as capture:
            logger.info("access %s", CANARY)
        assert capture.carrying(ACCESS_LOGGER, CANARY), "a non-propagating logger was missed"
    finally:
        logger.propagate = previous


def test_a_direct_stderr_write_is_captured_although_it_never_used_logging():
    """caplog would not see this at all."""
    with capturing_server_logs() as capture:
        sys.stderr.write(f"Traceback: {CANARY}\n")

    assert capture.carrying(STDERR, CANARY)
    assert not capture.carrying(ERROR_LOGGER, CANARY), "a raw stderr write was attributed to the error logger"


def test_the_sinks_do_not_bleed_into_one_another():
    with capturing_server_logs() as capture:
        logging.getLogger(ACCESS_LOGGER).info("only-access %s", CANARY)

    assert capture.carrying(ACCESS_LOGGER, CANARY)
    assert not capture.carrying(ERROR_LOGGER, CANARY)
    assert not capture.carrying(STDERR, CANARY)


def test_access_records_are_correlated_to_an_exchange():
    """A bare count over the sink includes every other request handled."""
    with capturing_server_logs() as capture:
        access = logging.getLogger(ACCESS_LOGGER)
        access.info('exchange-1 "GET /policies HTTP/1.1" 200')
        access.info('exchange-2 "GET /healthz HTTP/1.1" 200')
        access.info('exchange-1 "GET /policies HTTP/1.1" 200')

    assert len(capture.of(ACCESS_LOGGER)) == 3
    assert len(access_records_for(capture, "exchange-1")) == 2
    assert len(access_records_for(capture, "exchange-2")) == 1


def test_an_error_producer_witness_proves_the_sink_would_have_caught_one():
    with capturing_server_logs() as capture:
        logging.getLogger(ERROR_LOGGER).error("producer control %s", CANARY)
        capture.verify_producer(ERROR_LOGGER, CANARY)


def test_the_producer_witness_refuses_when_the_sink_saw_nothing():
    """An unattached capture reports the same silence as a clean run."""
    with pytest.raises(SinkNotObserved, match="proves nothing"):
        LogCapture().verify_producer(ERROR_LOGGER, CANARY)


def test_capture_is_removed_afterwards():
    """Otherwise every later test runs against a patched stderr and a logger
    carrying an extra handler."""
    logger = logging.getLogger(ERROR_LOGGER)
    before_handlers = list(logger.handlers)
    before_level = logger.level
    before_stderr = sys.stderr

    with capturing_server_logs():
        pass

    assert list(logger.handlers) == before_handlers
    assert logger.level == before_level
    assert sys.stderr is before_stderr


def test_records_are_captured_at_debug_level_not_only_the_default():
    """A sink left at WARNING silently drops the access records entirely."""
    with capturing_server_logs() as capture:
        logging.getLogger(ACCESS_LOGGER).debug("debug %s", CANARY)

    assert capture.carrying(ACCESS_LOGGER, CANARY)
