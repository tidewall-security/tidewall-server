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


# --- the runner exists and is wired in --------------------------------------


def test_the_runner_module_exists_and_calls_the_checkers():
    """These helpers had no caller outside this file.

    A well-tested set of comparison rules that never runs against anything is
    not a mutation step.
    """
    import pathlib

    runner = pathlib.Path(__file__).resolve().parent / "run_mutation_step.py"
    assert runner.exists()
    source = runner.read_text()
    assert "check_baseline(" in source
    assert "check_delta(" in source
    assert "verify_applied(" in source


def test_the_runner_is_a_required_ci_job():
    import pathlib

    import yaml

    workflow = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
    jobs = yaml.safe_load(workflow.read_text())["jobs"]
    assert "mutation-step" in jobs, sorted(jobs)

    steps = jobs["mutation-step"]["steps"]
    assert any("run_mutation_step.py" in s.get("run", "") for s in steps)
    for step in steps:
        assert step.get("continue-on-error") is not True


def test_the_runner_never_reads_an_exit_code():
    """While the baseline is red every run exits non-zero."""
    import pathlib

    source = (pathlib.Path(__file__).resolve().parent / "run_mutation_step.py").read_text()
    assert ".returncode" not in source


def test_the_recorded_baseline_exists_and_the_delta_falls_outside_it():
    """Otherwise the new signature is indistinguishable from a record that
    was already there."""
    import json
    import pathlib

    from tests.release.run_mutation_step import DEFAULT_MUTATION

    path = pathlib.Path(__file__).resolve().parent / "mutation_baseline.json"
    assert path.exists(), path
    baseline = Counter({tuple(k): v for k, v in json.loads(path.read_text())})
    assert delta_is_outside_baseline(DEFAULT_MUTATION, baseline)


def test_the_default_mutation_declares_a_count():
    """One signature affecting fourteen cases yields fourteen instances.

    Predeclaring only the signature would let a mutation that spread further
    than predicted pass.
    """
    from tests.release.run_mutation_step import DEFAULT_MUTATION

    assert DEFAULT_MUTATION.expected_count > 1


def test_a_wider_spread_than_predicted_fails():
    m = _mutation(expected_count=2)
    with pytest.raises(UnexpectedDelta):
        check_delta(m, BASELINE, BASELINE + Counter({SIG: 3}), harness_errors=0)
    check_delta(m, BASELINE, BASELINE + Counter({SIG: 2}), harness_errors=0)


def test_the_baseline_matches_what_the_suite_currently_emits():
    """Keys AND MULTIPLICITIES, against an independently derived expectation.

    Two earlier versions of this check were both satisfiable by a wrong
    baseline: one compared sets (so a MISSING entry passed), and the
    completeness check compared representation NAMES (so a corrupted COUNT
    passed -- changing a 1 to a 2 left all four baseline tests green).

    The independent derivation is the expected-failure manifest itself: its
    signatures are unique -- asserted separately -- so each predicts exactly
    one occurrence, and any baseline count other than that is drift.
    """
    import collections
    import json
    import pathlib

    from tests.release.expected_failures import generate
    from tests.release.manifest import load_cases

    path = pathlib.Path(__file__).resolve().parent / "mutation_baseline.json"
    recorded = collections.Counter({tuple(key): count for key, count in json.loads(path.read_text())})

    expected_signatures = collections.Counter(r.signature() for r in generate(load_cases()))
    assert all(n == 1 for n in expected_signatures.values()), (
        "the manifest no longer predicts each signature exactly once, so the " "count derivation below is invalid"
    )

    undeclared = sorted(set(recorded) - set(expected_signatures))
    assert not undeclared, f"the baseline holds signatures the manifest does not predict: {undeclared[:2]}"

    wrong_counts = {sig: n for sig, n in recorded.items() if n != 1}
    assert not wrong_counts, (
        f"the manifest predicts each signature once; the baseline records " f"{sorted(wrong_counts.items())[:2]}"
    )


def test_the_runner_proves_the_whole_suite_ran():
    """What the non-empty baseline was standing in for.

    This asserted the baseline was non-empty, because "an empty baseline hides
    the difference between nothing failed and the run produced no signatures at
    all". That was true, and the baseline was the wrong instrument for it: it
    supplied that evidence only incidentally, by being large. You cannot emit 255
    signatures without running the cases that emit them -- but that is a property
    of the number, not of the check, and it vanishes when the gate reaches the
    state it exists to reach and there is nothing left to accept.

    A run of zero tests satisfies `check_baseline(empty, empty)`. So does a
    REDUCED run that happens to emit the expected signatures, which the non-empty
    baseline never caught either.

    The release gate already had the right instrument: `--release-counts` records
    how many tests were selected after deselection, and `check_counts` compares
    that against `declared_counts.json` while refusing any deselection, skip or
    xfail. The mutation runner never asked for it. It does now, calling that same
    function rather than restating the rule.
    """
    import inspect

    from tests.release import run_mutation_step

    source = inspect.getsource(run_mutation_step.run_suite)
    assert "--release-counts" in source, "the runner does not ask how many tests ran"
    assert "check_counts" in source, "the runner does not check how many tests ran"

    # And the check it calls genuinely refuses a short run.
    import json
    import pathlib

    from tests.release.gate_report import DECLARED_COUNTS, SuiteResult, check_counts

    declared = json.loads(DECLARED_COUNTS.read_text())["release"]
    assert check_counts(SuiteResult(name="release", counts={"selected": 0}, declared=declared))
    assert check_counts(
        SuiteResult(name="release", counts={"selected": declared, "skipped": 1}, declared=declared)
    )
    assert not check_counts(
        SuiteResult(name="release", counts={"selected": declared}, declared=declared)
    )


def test_the_baseline_is_complete_over_the_families_it_covers():
    """Membership is not completeness.

    `baseline <= expected` passes for a baseline missing entries the suite
    emits -- a three-entry baseline satisfies it as well as a ten-entry one,
    and the runner then aborts at check_baseline with the job silently doing
    nothing.

    Every family present in the baseline must be present in FULL. The expected
    members are derived from the MANIFEST, not assumed: an earlier version
    hardcoded "all seven representation families", which is true of the
    validation-echo family and false of the access-rule ones -- so adding them
    made this test fail for the wrong reason.
    """
    import collections
    import json
    import pathlib

    from tests.release.expected_failures import generate
    from tests.release.manifest import load_cases

    def family_of(case_id: str) -> str:
        return case_id.rsplit("/", 1)[0]

    path = pathlib.Path(__file__).resolve().parent / "mutation_baseline.json"
    recorded = collections.defaultdict(set)
    for key, _count in json.loads(path.read_text()):
        recorded[family_of(key[0])].add(key[0])

    declared = collections.defaultdict(set)
    for record in generate(load_cases()):
        declared[family_of(record.case_id)].add(record.case_id)

    for family, members in sorted(recorded.items()):
        assert members == declared[family], {
            "family": family,
            "in the manifest, missing from the baseline": sorted(declared[family] - members),
            "in the baseline, not in the manifest": sorted(members - declared[family]),
        }


def test_a_skip_is_classified_as_unaccounted():
    """A SKIP IS NOT A PASS.

    A skip is neither an error nor a failure, so a mutation that DISABLES a
    test rather than breaking it escaped every check in the runner. A review
    constructed exactly that probe: a test that calls `pytest.skip` when it
    detects the mutant in the source.

    The gate already refuses any skip (`skipped == 0` per suite); the mutation
    step now sees them too.
    """
    import pathlib
    import xml.etree.ElementTree as ET

    source = (pathlib.Path(__file__).resolve().parent / "run_mutation_step.py").read_text()
    assert 'case.find("skipped")' in source, (
        "the runner no longer inspects skipped outcomes, so a mutant that "
        "disables a test rather than breaking it would pass"
    )

    # And the classification is reachable: a JUnit skip parses as such.
    xml = ET.fromstring(
        '<testsuites><testsuite><testcase classname="a" name="b">'
        '<skipped message="x"/></testcase></testsuite></testsuites>'
    )
    case = next(xml.iter("testcase"))
    assert case.find("skipped") is not None
    assert case.find("failure") is None and case.find("error") is None


def test_a_failure_must_carry_the_signature_that_caused_it():
    """Emitting a signature does not excuse an unrelated failure.

    The runner accounted a failure whenever the same test node had emitted any
    signature, never establishing that the signature CAUSED the failure. A
    review probed it: a test that records a signature and then fails an
    unrelated assertion was accepted. So a mutation could make an
    already-emitting test fail for a different reason and pass unnoticed.

    The failure message now carries its own signature, and the runner requires
    the carried signature to be one that test emitted.
    """
    import pathlib

    from tests.release.signatures import (
        FAILURE_MARKER,
        ExpectedSecurityFailure,
        Signature,
        encode,
        signatures_in,
    )

    signature = Signature("c", "p", "col", "path", "plain", "FORBIDDEN")
    message = str(ExpectedSecurityFailure(signature, "detail"))

    assert FAILURE_MARKER in message
    assert signatures_in(message) == {encode(signature)}
    assert (
        signatures_in("an unrelated assertion failed") == set()
    ), "an unrelated message must carry no signature at all"

    source = (pathlib.Path(__file__).resolve().parent / "run_mutation_step.py").read_text()
    assert "signatures_in(message)" in source, "the runner no longer reads the signature carried by the failure"


def test_the_baseline_equals_the_manifest_exactly():
    """The strongest form, available now that reconciliation is complete.

    Every one of the manifest's 255 records genuinely occurs, so the baseline
    IS the manifest -- keys and multiplicities. That is independently derived
    (the manifest is checked-in data with its own generator and oracles) and it
    subsumes every earlier drift check:

      * a MISSING entry fails -- the gap that let the mutation job silently
        stop mutating, twice;
      * an EXTRA entry fails -- a signature nobody declared;
      * a CORRUPTED COUNT fails -- the manifest predicts each signature once.

    The earlier version listed emitting families by hand, which needed editing
    every time a suite started emitting a new one. That list was itself a thing
    that could go stale.
    """
    import collections
    import json
    import pathlib

    from tests.release.expected_failures import generate
    from tests.release.manifest import load_cases

    path = pathlib.Path(__file__).resolve().parent / "mutation_baseline.json"
    recorded = collections.Counter({tuple(key): count for key, count in json.loads(path.read_text())})
    expected = collections.Counter(r.signature() for r in generate(load_cases()))

    missing = expected - recorded
    extra = recorded - expected
    assert not missing and not extra, {
        "in the manifest, missing from the baseline": sorted(missing)[:2],
        "in the baseline, not in the manifest": sorted(extra)[:2],
    }
