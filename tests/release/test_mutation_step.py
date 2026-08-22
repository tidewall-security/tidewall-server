"""The mutation step compares multisets, and refuses every substitute."""

from __future__ import annotations

from collections import Counter

import pytest

from tests.release.mutation_step import (
    BaselineMismatch,
    HarnessErrorSubstituted,
    Mutation,
    MutationNotApplied,
    UnexpectedDelta,
    check_baseline,
    check_delta,
    delta_is_outside_baseline,
    verify_applied,
)

SIG = ("case-1", "FORBIDDEN occurrence reached a surface", "database", "$.x", "plain", "FORBIDDEN")
BASELINE = Counter({("case-0", "p", "c", "$.y", "plain", "FORBIDDEN"): 1})


def _mutation(**kw) -> Mutation:
    base = dict(
        name="drop-the-resolver-call",
        path="tests/release/consumer.py",
        old="    for occurrence in emitted:",
        new="    for occurrence in []:",
        expected_signature=SIG,
    )
    base.update(kw)
    return Mutation(**base)


# --- the mutation must be proven applied ------------------------------------


def test_an_anchor_that_does_not_match_is_refused():
    """An edit that silently failed produces an identical multiset, which
    reads as a surviving mutant."""
    with pytest.raises(MutationNotApplied, match="anchor not found"):
        _mutation().apply("unrelated source")


def test_an_ambiguous_anchor_is_refused():
    """Two matches means the edit landed somewhere unintended."""
    source = "    for occurrence in emitted:\n    for occurrence in emitted:\n"
    with pytest.raises(MutationNotApplied, match="matches 2 times"):
        _mutation().apply(source)


def test_an_unchanged_source_is_refused():
    with pytest.raises(MutationNotApplied, match="source unchanged"):
        verify_applied(_mutation(), "same", "same")


def test_a_real_edit_passes_both_checks():
    source = "x = 1\n    for occurrence in emitted:\ny = 2\n"
    after = _mutation().apply(source)
    verify_applied(_mutation(), source, after)
    assert "for occurrence in []:" in after


# --- the unmutated run must reproduce the baseline exactly ------------------


def test_a_superset_baseline_is_refused():
    """ "The baseline plus some noise" cannot attribute a later delta."""
    observed = BASELINE + Counter({SIG: 1})
    with pytest.raises(BaselineMismatch, match="extra="):
        check_baseline(observed, BASELINE)


def test_a_subset_baseline_is_refused():
    with pytest.raises(BaselineMismatch, match="missing="):
        check_baseline(Counter(), BASELINE)


def test_an_exact_baseline_passes():
    check_baseline(Counter(BASELINE), BASELINE)


# --- the delta must be exactly one predeclared signature --------------------


def test_the_expected_single_novel_signature_passes():
    check_delta(_mutation(), BASELINE, BASELINE + Counter({SIG: 1}), harness_errors=0)


def test_no_delta_at_all_is_refused():
    """A surviving mutant."""
    with pytest.raises(UnexpectedDelta, match="expected exactly"):
        check_delta(_mutation(), BASELINE, Counter(BASELINE), harness_errors=0)


def test_two_novel_signatures_are_refused():
    other = ("case-2", "p", "c", "$.z", "plain", "FORBIDDEN")
    mutant = BASELINE + Counter({SIG: 1, other: 1})
    with pytest.raises(UnexpectedDelta):
        check_delta(_mutation(), BASELINE, mutant, harness_errors=0)


def test_a_different_novel_signature_is_refused():
    """The mutant broke something -- just not the thing predicted."""
    other = ("case-9", "p", "c", "$.other", "plain", "FORBIDDEN")
    with pytest.raises(UnexpectedDelta):
        check_delta(_mutation(), BASELINE, BASELINE + Counter({other: 1}), harness_errors=0)


def test_a_delta_that_also_removes_a_baseline_record_is_refused():
    """One novel signature, not a rearrangement."""
    mutant = Counter({SIG: 1})
    with pytest.raises(UnexpectedDelta, match="also REMOVED"):
        check_delta(_mutation(), BASELINE, mutant, harness_errors=0)


# --- a harness error may not substitute -------------------------------------


def test_a_harness_error_is_refused_even_when_the_delta_looks_right():
    """A collection failure changes the multiset too.

    Counting it as the expected delta means the mutation was never exercised.
    """
    with pytest.raises(HarnessErrorSubstituted, match="not exercised"):
        check_delta(_mutation(), BASELINE, BASELINE + Counter({SIG: 1}), harness_errors=1)


# --- while the baseline is red -----------------------------------------------


def test_a_delta_already_in_the_baseline_is_rejected_as_a_choice():
    """Otherwise the new signature is indistinguishable from a record that
    was already there."""
    inside = _mutation(expected_signature=next(iter(BASELINE)))
    assert not delta_is_outside_baseline(inside, BASELINE)
    assert delta_is_outside_baseline(_mutation(), BASELINE)


def test_the_step_never_reads_an_exit_code():
    """Stated in the suite.

    While the baseline is red every run exits non-zero, so an exit code
    carries no information.
    """
    import pathlib

    source = (pathlib.Path(__file__).resolve().parent / "mutation_step.py").read_text()
    assert "returncode" not in source
    assert "exit" not in source.split('"""')[2] if '"""' in source else True
