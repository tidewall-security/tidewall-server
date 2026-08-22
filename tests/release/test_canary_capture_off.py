"""Capture OFF, driven through PRODUCTION.

The expected count is ZERO, in every artifact. There is no "it was only
historical" allowance: with capture off nothing was ever supposed to write the
value, so an occurrence in a WAL frame is a write that happened.

An earlier version of this file asserted its case list matched the manifest
and then ran synthetic checks over hand-built objects. A review neutered
`EmojiDetector.scan` and it still passed 170/170. Every assertion below now
runs the real engine, and a case that CANNOT run here is reported with its
reason rather than counted as a pass.
"""

from __future__ import annotations

import pytest

from tests.release.canary_suite import SUITE_STATE, cases_for, diagnose
from tests.release.execution import (
    SELF_CONTAINED_DETECTORS,
    CaseNotExecutable,
    chain_for,
    execute,
    witnesses_for,
)
from tests.release.manifest import load_cases
from tests.release.signatures import RECORDER, Signature
from tests.release.witnesses import AbsenceEvaluator, assert_absent, gate

CASES = cases_for("capture-off")
MANIFEST_CASES = {c.identity: c for c in load_cases()}
EXECUTABLE = [c for c in CASES if c.detector in SELF_CONTAINED_DETECTORS]


def test_the_suite_covers_every_capture_off_case_in_the_manifest():
    declared = {c.identity for c in load_cases() if c.capture.value == "capture-off"}
    assert {c.case_id for c in CASES} == declared


def test_every_case_has_a_distinct_canary():
    """A shared canary makes one case's leak look like another's."""
    canaries = [c.canary for c in CASES]
    assert len(set(canaries)) == len(canaries)


def test_some_cases_are_executable_here():
    """If none were, every execution test below would vacuously pass."""
    assert EXECUTABLE, "no capture-off case can run in this environment"


def test_the_unexecutable_cases_are_reported_rather_than_counted_as_passes():
    """A case that did not run has not passed.

    The count is stated so a shrinking executable set is visible rather than
    silently reducing coverage.
    """
    unexecutable = [c for c in CASES if c.detector not in SELF_CONTAINED_DETECTORS]
    assert len(EXECUTABLE) + len(unexecutable) == len(CASES)
    assert len(EXECUTABLE) >= 50, f"only {len(EXECUTABLE)} of {len(CASES)} capture-off cases can run here"


@pytest.mark.parametrize("case", EXECUTABLE, ids=lambda c: c.case_id[:48])
def test_the_case_runs_and_the_canary_reaches_the_detector(case):
    """The evaluated-input witness, from a real run."""
    execution = execute(MANIFEST_CASES[case.case_id], case.canary)
    assert execution.received, diagnose(case, "the detector received nothing")
    # Compare against what was PLANTED, not the raw canary. A leaf shape may
    # normalise case -- an email is lowercased -- so asserting on the raw
    # canary fails on a correctly shaped value.
    assert execution.received[0] == execution.planted, diagnose(
        case, f"detector received {execution.received[0]!r}, planted {execution.planted!r}"
    )
    assert case.canary.lower() in execution.planted.lower(), diagnose(
        case, f"the shape dropped the canary: {execution.planted!r}"
    )


@pytest.mark.parametrize("case", EXECUTABLE, ids=lambda c: c.case_id[:48])
def test_no_occurrence_of_the_canary_reaches_any_surface(case):
    """The property, against surfaces the run actually produced.

    Every occurrence found emits a six-field signature so the gate can
    reconcile it against the expected-failure manifest rather than counting.
    """
    execution = execute(MANIFEST_CASES[case.case_id], case.canary)
    found = execution.occurrences_of(case.canary)

    for surface, count in sorted(found.items()):
        RECORDER.record(
            Signature(
                case_id=case.case_id,
                property="FORBIDDEN occurrence reached a surface",
                collector="scan-result",
                surface_path=f"ScanResult.{surface}",
                representation=case.representation,
                occurrence_rule="FORBIDDEN",
            )
        )

    assert not found, diagnose(case, f"capture-off expects zero occurrences, found {found}")


@pytest.mark.parametrize("case", EXECUTABLE, ids=lambda c: c.case_id[:48])
def test_absence_is_asserted_only_behind_a_complete_witness(case):
    """The gate, on witnesses built from what was observed.

    Without this the assertion above is equally true of a case whose detector
    never ran.
    """
    execution = execute(MANIFEST_CASES[case.case_id], case.canary)
    manifest_case = MANIFEST_CASES[case.case_id]

    try:
        ingress, outcome, collector = witnesses_for(execution, store_rows=1)
    except CaseNotExecutable as exc:
        pytest.fail(diagnose(case, str(exc)))

    chain = chain_for(execution, manifest_case)
    # The outcome names the detector that ran, which is what the chain must
    # declare for the gate to accept it.
    chain = type(chain)(**{**chain.__dict__, "component": execution.detector})

    gate(
        chain,
        ingress=ingress,
        outcome=outcome,
        collector=collector,
        declared_object_count=len(execution.surfaces()),
    )

    evaluator = AbsenceEvaluator()
    assert_absent(
        chain,
        ingress=ingress,
        outcome=outcome,
        collector=collector,
        declared_object_count=len(execution.surfaces()),
        found=bool(execution.occurrences_of(case.canary)),
        evaluator=evaluator,
    )
    assert evaluator.called_for(case.case_id)


def test_a_failure_diagnostic_carries_the_replay_identifier():
    """A run artifact nobody reads is not a reproduction aid."""
    message = diagnose(CASES[0], "example")
    assert SUITE_STATE.identifier in message
    assert f"case={CASES[0].case_id}" in message


@pytest.mark.parametrize("case", EXECUTABLE, ids=lambda c: c.case_id[:48])
def test_the_case_reaches_the_component_it_declares(case):
    """Task 5's rule, applied per case in the suite that runs the case.

    Absence properties cannot catch a detector that stopped detecting: a
    detector reporting nothing produces FEWER surfaces, so "the canary reached
    no surface" becomes MORE true. Neutering EmojiDetector.scan left the
    absence assertions above passing 164/164.

    What it does break is the declared component: the case says it exercises
    emoji/reported, and with the mutant that state is never reached.
    """
    from tests.release.observation import verify_declared_component

    manifest_case = MANIFEST_CASES[case.case_id]
    execution = execute(manifest_case, case.canary)
    declared = f"{manifest_case.component}/{manifest_case.sub_path}"

    verify_declared_component(diagnose(case, declared), declared, execution.components)
