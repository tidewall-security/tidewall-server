"""Boundary counters, counted AT THEIR OWN BOUNDARIES.

Counting at the wrong boundary is how a count reads plausible and measures
something else. Three cases this suite refuses:

  * counting HTTP exchanges by log records -- a request that logs twice reads
    as two requests, and one that logs nothing reads as zero;
  * counting transport calls by responses -- a call that fails carries no
    response and vanishes from the count;
  * counting browser network requests by DOM nodes -- an image that never
    loads still has its node.

Each boundary counts its own objects, and the count is compared with what that
boundary declared.
"""

from __future__ import annotations

import pytest

from tests.release.boundaries import (
    REQUIRED_BOUNDARIES,
    BoundaryError,
    BoundarySet,
    http_exchange_identity,
)

COUNTED_BOUNDARIES = (
    "http",
    "transport",
    "logs",
    "dom",
    "storage",
    "console",
    "browser-network",
)


def _registry() -> BoundarySet:
    s = BoundarySet()
    for name in REQUIRED_BOUNDARIES:
        s.register(name)
    return s


def test_every_counted_boundary_is_a_declared_boundary():
    """A counter for a boundary nobody declared counts into nothing."""
    assert set(COUNTED_BOUNDARIES) <= REQUIRED_BOUNDARIES


@pytest.mark.parametrize("name", COUNTED_BOUNDARIES)
def test_each_boundary_counts_its_own_objects(name: str):
    s = _registry()
    b = s.boundaries[name]
    b.declare(f"{name}-object-a", count=2)
    b.declare(f"{name}-object-b", count=1)
    b.record(f"{name}-object-a", count=2)
    b.record(f"{name}-object-b", count=1)
    s.check()


@pytest.mark.parametrize("name", COUNTED_BOUNDARIES)
def test_each_boundary_reports_its_own_count_mismatch(name: str):
    s = _registry()
    b = s.boundaries[name]
    b.declare(f"{name}-object", count=1)
    b.record(f"{name}-object", count=2)
    with pytest.raises(BoundaryError, match=f"{name}:"):
        s.check()


def test_http_exchanges_are_not_counted_by_log_records():
    """A request that logs twice is still one request.

    Counting exchanges from the log boundary reports two, and the number looks
    entirely reasonable.
    """
    s = _registry()
    exchange = http_exchange_identity("GET", "/policies", 200, {}, b"{}")

    s.boundaries["http"].declare(exchange, count=1)
    s.boundaries["http"].record(exchange, count=1)

    s.boundaries["logs"].declare("request.received", count=1)
    s.boundaries["logs"].declare("request.completed", count=1)
    s.boundaries["logs"].record("request.received", count=1)
    s.boundaries["logs"].record("request.completed", count=1)

    s.check()
    assert sum(s.boundaries["http"].produced.values()) == 1
    assert sum(s.boundaries["logs"].produced.values()) == 2


def test_a_silent_request_still_counts_at_the_http_boundary():
    """The same error in the other direction: an exchange that logs nothing."""
    s = _registry()
    exchange = http_exchange_identity("GET", "/healthz", 200, {}, b"")
    s.boundaries["http"].declare(exchange)
    s.boundaries["http"].record(exchange)
    s.check()

    assert sum(s.boundaries["http"].produced.values()) == 1
    assert sum(s.boundaries["logs"].produced.values()) == 0


def test_a_failed_transport_call_is_counted_even_with_no_response():
    """Counting calls by responses loses every call that failed.

    Which is exactly the call most worth counting.
    """
    s = _registry()
    s.boundaries["transport"].declare("POST https://intel.example/lookup", count=1)
    s.boundaries["transport"].record("POST https://intel.example/lookup", count=1)
    s.check()

    assert sum(s.boundaries["transport"].produced.values()) == 1
    assert sum(s.boundaries["http"].produced.values()) == 0


def test_an_undeclared_transport_call_fails():
    """An egress nobody declared is the finding, not a counting detail."""
    s = _registry()
    s.boundaries["transport"].record("POST https://unknown.example/collect")
    with pytest.raises(BoundaryError, match="transport: produced-not-declared"):
        s.check()


def test_browser_network_is_not_counted_by_dom_nodes():
    """An image node that never issues a request.

    Counting network activity from the DOM reports a request that did not
    happen -- and, worse, reports zero for a fetch that leaves no node.
    """
    s = _registry()
    s.boundaries["dom"].declare("img#logo", count=1)
    s.boundaries["dom"].record("img#logo", count=1)
    s.check()

    assert sum(s.boundaries["dom"].produced.values()) == 1
    assert sum(s.boundaries["browser-network"].produced.values()) == 0


def test_a_fetch_with_no_dom_node_still_counts_at_the_network_boundary():
    s = _registry()
    s.boundaries["browser-network"].declare("GET /api/policies", count=1)
    s.boundaries["browser-network"].record("GET /api/policies", count=1)
    s.check()

    assert sum(s.boundaries["browser-network"].produced.values()) == 1
    assert sum(s.boundaries["dom"].produced.values()) == 0


def test_storage_and_console_are_counted_separately():
    """Two browser surfaces the drafts kept collapsing into one."""
    s = _registry()
    s.boundaries["storage"].declare("localStorage:last-policy", count=1)
    s.boundaries["storage"].record("localStorage:last-policy", count=1)
    s.boundaries["console"].declare("warn:deprecated-field", count=2)
    s.boundaries["console"].record("warn:deprecated-field", count=2)
    s.check()

    assert sum(s.boundaries["storage"].produced.values()) == 1
    assert sum(s.boundaries["console"].produced.values()) == 2


def test_a_count_at_one_boundary_does_not_satisfy_another():
    """The failure this whole module is about.

    Recording the exchange at the log boundary leaves the HTTP boundary
    declared-but-not-produced, and the log boundary produced-but-not-declared.
    Both directions fire.
    """
    s = _registry()
    exchange = http_exchange_identity("GET", "/policies", 200, {}, b"{}")
    s.boundaries["http"].declare(exchange, count=1)
    s.boundaries["logs"].record(exchange, count=1)

    with pytest.raises(BoundaryError) as exc:
        s.check()
    assert "http: declared-not-produced" in str(exc.value)
    assert "logs: produced-not-declared" in str(exc.value)
