"""Outbound transport, against a real httpx client."""

from __future__ import annotations

import httpx
import pytest

from tests.release.transport import (
    Invocation,
    TransportNotObserved,
    TransportRecorder,
    recording_transport,
)

SENTINEL = b"CANARY-EGRESS-2b6f"


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"ok": True})


def test_the_submitted_body_bytes_are_recorded():
    """What went on the wire, not what a caller handed to the client."""
    with recording_transport(httpx) as recorder:
        with _client(_ok) as client:
            client.post("https://intel.example/lookup", json={"q": SENTINEL.decode()})

    assert recorder.bodies(), "no outbound body was recorded"
    assert SENTINEL in recorder.bodies()[0], recorder.bodies()


def test_serialisation_happens_between_the_caller_and_the_wire():
    """The reason the body must be read at the transport.

    The caller passed a dict; the wire carried JSON bytes. Asserting on the
    dict checks a value that was never transmitted.
    """
    payload = {"q": SENTINEL.decode()}
    with recording_transport(httpx) as recorder:
        with _client(_ok) as client:
            client.post("https://intel.example/lookup", json=payload)

    body = recorder.bodies()[0]
    assert isinstance(body, bytes)
    assert body != str(payload).encode()
    assert body.startswith(b"{")


def test_a_retry_is_counted_as_two_invocations():
    with recording_transport(httpx) as recorder:
        with _client(_ok) as client:
            client.get("https://intel.example/health")
            client.get("https://intel.example/health")

    assert recorder.count("GET https://intel.example/health") == 2


def test_a_failed_call_is_still_counted():
    """Counting responses loses the call most worth counting."""

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with recording_transport(httpx) as recorder:
        with _client(boom) as client:
            with pytest.raises(httpx.ConnectError):
                client.post("https://intel.example/lookup", content=SENTINEL)

    assert len(recorder.invocations) == 1
    assert recorder.invocations[0].raised == "ConnectError"
    assert recorder.carries(SENTINEL), "the failed call's body was lost"


def test_the_producer_control_sees_its_own_egress():
    """The control that makes an absence assertion mean anything."""
    with recording_transport(httpx) as recorder:
        with _client(_ok) as client:
            client.post("https://control.example/probe", content=SENTINEL)
        recorder.verify_producer_control(SENTINEL)


def test_the_producer_control_refuses_when_nothing_was_seen():
    """A recorder that was never attached reports the same absence as a
    system that made no calls."""
    with pytest.raises(TransportNotObserved, match="proves nothing"):
        TransportRecorder().verify_producer_control(SENTINEL)


def test_the_control_uses_the_same_recorder_as_the_assertion():
    """A control with its own recorder proves the control's recorder works."""
    with recording_transport(httpx) as recorder:
        with _client(_ok) as client:
            client.post("https://control.example/probe", content=SENTINEL)
            client.post("https://intel.example/lookup", content=b"no canary here")

        recorder.verify_producer_control(SENTINEL)
        real = [i for i in recorder.invocations if "intel.example" in i.url]
        assert real, "the assertion's own call was not recorded"
        assert not [i for i in real if SENTINEL in i.body]


def test_the_patch_is_removed_afterwards():
    original = httpx.Client.send
    with recording_transport(httpx):
        assert httpx.Client.send is not original
    assert httpx.Client.send is original


def test_invocation_identity_ignores_the_body():
    a = Invocation("POST", "https://x/y", b"one")
    b = Invocation("POST", "https://x/y", b"two")
    assert a.identity == b.identity == "POST https://x/y"


def test_the_count_is_per_identity_not_a_total():
    """Two endpoints, different counts.

    A test that only ever calls one URL cannot tell a per-identity count from
    a total, and a regression to the total passes it.
    """
    with recording_transport(httpx) as recorder:
        with _client(_ok) as client:
            client.get("https://intel.example/health")
            client.get("https://intel.example/health")
            client.post("https://intel.example/lookup", content=b"x")

    assert len(recorder.invocations) == 3
    assert recorder.count("GET https://intel.example/health") == 2
    assert recorder.count("POST https://intel.example/lookup") == 1
    assert recorder.count("GET https://never.example/") == 0
