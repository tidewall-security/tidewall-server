"""Declared object sets at every non-database boundary."""

from __future__ import annotations

import pytest

from tests.release.boundaries import (
    REQUIRED_BOUNDARIES,
    BoundaryError,
    BoundarySet,
    MissingBoundary,
    http_exchange_identity,
)


def _complete() -> BoundarySet:
    s = BoundarySet()
    for name in REQUIRED_BOUNDARIES:
        s.register(name)
    return s


def test_the_browser_surfaces_are_all_required():
    """The omission that recurred across three drafts.

    v3 dropped the browser entirely; v4 listed four of its surfaces and lost
    page state, which the design names separately.
    """
    assert {"dom", "page-state", "storage", "console", "browser-network"} <= REQUIRED_BOUNDARIES


def test_the_non_browser_surfaces_are_all_required():
    assert {"http", "transport", "logs", "artifacts"} <= REQUIRED_BOUNDARIES


def test_a_missing_boundary_is_refused_not_skipped():
    """A boundary absent from the registry is absent from the check."""
    s = BoundarySet()
    s.register("http")
    with pytest.raises(MissingBoundary, match="never registered"):
        s.check()


def test_the_error_names_every_absent_boundary():
    s = BoundarySet()
    s.register("http")
    with pytest.raises(MissingBoundary) as exc:
        s.verify_complete()
    for name in REQUIRED_BOUNDARIES - {"http"}:
        assert name in str(exc.value)


def test_an_unknown_boundary_name_is_refused():
    """A typo registers a boundary nobody checks and satisfies nothing."""
    s = BoundarySet()
    with pytest.raises(MissingBoundary, match="not a declared boundary"):
        s.register("htp")


def test_a_produced_object_that_was_not_declared_fails():
    s = _complete()
    s.boundaries["logs"].record("audit.policy_applied")
    with pytest.raises(BoundaryError, match="produced-not-declared"):
        s.check()


def test_a_declared_object_that_was_not_produced_fails():
    """The stale declaration, at a non-database boundary."""
    s = _complete()
    s.boundaries["transport"].declare("POST https://intel.example/lookup")
    with pytest.raises(BoundaryError, match="declared-not-produced"):
        s.check()


def test_a_count_mismatch_fails_even_when_the_identities_agree():
    """Two exchanges with one identity are two exchanges."""
    s = _complete()
    s.boundaries["http"].declare("GET /policies -> 200", count=1)
    s.boundaries["http"].record("GET /policies -> 200", count=2)
    with pytest.raises(BoundaryError, match="declared 1, produced 2"):
        s.check()


def test_agreement_at_every_boundary_passes():
    s = _complete()
    s.boundaries["http"].declare("GET /policies -> 200")
    s.boundaries["http"].record("GET /policies -> 200")
    s.boundaries["console"].declare("warn:deprecated-field", count=3)
    s.boundaries["console"].record("warn:deprecated-field", count=3)
    s.check()


def test_an_empty_but_registered_boundary_passes():
    """Declaring nothing and producing nothing is agreement."""
    _complete().check()


def test_the_http_identity_includes_every_header_not_just_the_body():
    """The Content-Disposition case.

    A body-derived inventory never looks at the header `policy.name` appears
    in, and passes its own controls the whole time.
    """
    body = b"{}"
    without = http_exchange_identity("GET", "/export", 200, {}, body)
    with_header = http_exchange_identity(
        "GET",
        "/export",
        200,
        {"Content-Disposition": 'attachment; filename="my-policy.json"'},
        body,
    )
    assert without != with_header
    assert "my-policy.json" in with_header


def test_the_http_identity_includes_the_status():
    a = http_exchange_identity("GET", "/x", 200, {}, b"")
    b = http_exchange_identity("GET", "/x", 500, {}, b"")
    assert a != b


def test_the_http_identity_includes_the_body_size():
    a = http_exchange_identity("GET", "/x", 200, {}, b"")
    b = http_exchange_identity("GET", "/x", 200, {}, b"leaked")
    assert a != b


def test_header_order_and_case_do_not_change_the_identity():
    """Two spellings of the same exchange must not read as two exchanges."""
    a = http_exchange_identity("GET", "/x", 200, {"A": "1", "B": "2"}, b"")
    b = http_exchange_identity("GET", "/x", 200, {"b": "2", "a": "1"}, b"")
    assert a == b
