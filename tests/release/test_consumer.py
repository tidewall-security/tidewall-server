"""Both resolver directions, and the four mutations named by the plan."""

from __future__ import annotations

import pytest

from tests.release.consumer import (
    Emitted,
    ForbiddenOccurrence,
    RequiredOccurrenceMissing,
    UnresolvedOccurrence,
    check_allowed_bounded_is_confined,
    check_emitted_are_resolved,
    check_required_are_emitted,
    route,
)
from tests.release.occurrences import Rule


def _emitted(**kw) -> Emitted:
    base = dict(
        case_id="case-1",
        leaf="random-canary",
        placement="message-content",
        branch="allow",
        detector="malicious_prompt",
        event="input",
        capture="capture-off",
        operation="guard",
        grant="api",
        representation="plain",
        path="POST /v1/guard_chat_completions -> $.summary",
    )
    base.update(kw)
    return Emitted(**base)


# --- direction 1: emitted -> resolved ---------------------------------------


def test_every_emitted_occurrence_is_routed_through_the_real_resolver():
    row = route(_emitted())
    assert row.rule in tuple(Rule)


def test_a_forbidden_occurrence_fails():
    """FORBIDDEN applies BY DEFAULT over the enumerated surfaces.

    An occurrence in the domain with no more specific rule is forbidden, not
    unclassified.
    """
    with pytest.raises(ForbiddenOccurrence, match="FORBIDDEN occurrence reached"):
        check_emitted_are_resolved([_emitted()])


def test_the_shipped_matrix_resolves_everything_by_default():
    """FORBIDDEN by default is a real row, not an absence of rules.

    So a zero-match failure cannot arise against the shipped matrix, and the
    tests below use an explicit row set to produce one.
    """
    from tests.release.occurrences import ROWS

    catchall = [
        r
        for r in ROWS
        if all(
            getattr(r, axis) == "*"
            for axis in (
                "leaf",
                "placement",
                "branch",
                "detector",
                "event",
                "capture",
                "operation",
                "grant",
                "representation",
                "path",
            )
        )
    ]
    assert len(catchall) == 1, catchall
    assert catchall[0].rule is Rule.FORBIDDEN
    assert route(_emitted(leaf="not-a-declared-leaf")).rule is Rule.FORBIDDEN


def test_a_zero_match_occurrence_is_reported_as_unresolved():
    """Mutation: a zero-match occurrence.

    Distinct from forbidden -- an unresolved occurrence means the matrix has
    nothing to say, which is a different fix from a rule that says no.
    """
    with pytest.raises(UnresolvedOccurrence, match="NoRule"):
        route(_emitted(), rows=())


def test_an_ambiguous_two_match_occurrence_is_reported_as_unresolved():
    """Mutation: an ambiguous two-match occurrence.

    Two rules of equal specificity is not "pick one"; it means the matrix
    disagrees with itself and no answer is trustworthy.
    """
    from tests.release.occurrences import Row

    axes = _emitted().axes()
    duplicate = Row(**axes, rule=Rule.ALLOWED_BOUNDED, why="one")
    other = Row(**axes, rule=Rule.REQUIRED, why="two")

    with pytest.raises(UnresolvedOccurrence, match="Ambiguous"):
        route(_emitted(), rows=(duplicate, other))


def test_a_single_exact_match_resolves_cleanly():
    """The control: the same construction with one row does resolve."""
    from tests.release.occurrences import Row

    only = Row(**_emitted().axes(), rule=Rule.REQUIRED, why="only")
    assert route(_emitted(), rows=(only,)).rule is Rule.REQUIRED


# --- direction 2: required -> emitted ---------------------------------------


def test_a_required_occurrence_that_was_never_emitted_fails():
    """The failure direction 1 structurally cannot see.

    Nothing was emitted, so nothing was routed, so nothing was unresolved.
    """
    required = [_emitted(case_id="case-required", path="$.matches_json")]
    with pytest.raises(RequiredOccurrenceMissing, match="never emitted"):
        check_required_are_emitted(emitted=[], required=required)


def test_direction_one_reports_nothing_for_that_same_absence():
    """Stated as a test, because it is the reason both directions exist."""
    check_emitted_are_resolved([])


def test_a_required_occurrence_that_was_emitted_passes():
    required = [_emitted(case_id="case-required", path="$.matches_json")]
    check_required_are_emitted(emitted=list(required), required=required)


def test_the_comparison_is_a_multiset_not_a_set():
    """Required twice, emitted once, is a failure.

    A set comparison reports agreement and the shortfall never surfaces.
    """
    one = _emitted(case_id="case-required", path="$.matches_json")
    with pytest.raises(RequiredOccurrenceMissing, match="x1"):
        check_required_are_emitted(emitted=[one], required=[one, one])


def test_a_surplus_emission_is_not_a_missing_required_occurrence():
    """Direction 2 is about absence. A surplus is direction 1's business."""
    one = _emitted(case_id="case-required", path="$.matches_json")
    check_required_are_emitted(emitted=[one, one], required=[one])


# --- ALLOWED-BOUNDED is confined --------------------------------------------


def test_allowed_bounded_at_an_unlisted_sibling_path_fails():
    """Optional, but only where enumerated."""
    from tests.release.occurrences import ROWS

    bounded = next((r for r in ROWS if r.rule is Rule.ALLOWED_BOUNDED), None)
    if bounded is None:
        pytest.skip("no ALLOWED-BOUNDED row in the matrix")

    occurrence = _emitted(
        leaf=bounded.leaf if bounded.leaf != "*" else "random-canary",
        placement=bounded.placement if bounded.placement != "*" else "message-content",
        branch=bounded.branch if bounded.branch != "*" else "allow",
        detector=bounded.detector if bounded.detector != "*" else "malicious_prompt",
        event=bounded.event if bounded.event != "*" else "input",
        capture=bounded.capture if bounded.capture != "*" else "capture-off",
        operation=bounded.operation if bounded.operation != "*" else "guard",
        grant=bounded.grant if bounded.grant != "*" else "api",
        representation=bounded.representation if bounded.representation != "*" else "plain",
        path=bounded.path if bounded.path != "*" else "$.declared",
    )
    resolved = route(occurrence)
    if resolved.rule is not Rule.ALLOWED_BOUNDED:
        pytest.skip("the constructed axes do not resolve to ALLOWED-BOUNDED")

    check_allowed_bounded_is_confined([occurrence], {occurrence.path})
    with pytest.raises(ForbiddenOccurrence, match="unlisted path"):
        check_allowed_bounded_is_confined([occurrence], {"$.some-other-path"})


# --- mutation: a collector that bypasses the resolver ------------------------


def test_an_occurrence_that_never_reaches_the_resolver_is_the_failure_mode():
    """Mutation: a collector emitting an occurrence that bypasses resolve().

    Modelled by asserting the checker ROUTES what it is given: an
    implementation that inspects the occurrence itself would pass a forbidden
    one that the matrix has no row for.
    """
    calls = []

    class Recording(Emitted):
        def axes(self):
            calls.append(self.path)
            return super().axes()

    occurrence = Recording(**{**_emitted().__dict__})
    with pytest.raises(ForbiddenOccurrence):
        check_emitted_are_resolved([occurrence])

    assert calls == [occurrence.path], "the occurrence never reached the resolver, so no rule was applied"
