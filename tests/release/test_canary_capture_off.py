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
    encode_for,
    execute,
    is_not_evaluated,
    witnesses_for,
)
from tests.release.manifest import load_cases
from tests.release.representations import FAMILIES
from tests.release.signatures import RECORDER, Signature
from tests.release.witnesses import AbsenceEvaluator, assert_absent, gate

CASES = cases_for("capture-off")
MANIFEST_CASES = {c.identity: c for c in load_cases()}
EXECUTABLE = [c for c in CASES if c.detector in SELF_CONTAINED_DETECTORS]

#: Measured, and pinned so a shrinking set is visible rather than silent.
EXPECTED_EXECUTABLE = 53

#: Cases whose component NEVER READS their leaf. They must not go through the
#: ordinary declared-component check: the component is reached, but for
#: reasons having nothing to do with the planted value. A review proved it by
#: running the same case with two entirely different values and observing the
#: identical component both times.
NOT_EVALUATED_CASES = [c for c in EXECUTABLE if is_not_evaluated(MANIFEST_CASES[c.case_id])]
EVALUATED_CASES = [c for c in EXECUTABLE if not is_not_evaluated(MANIFEST_CASES[c.case_id])]


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
    # PINNED, not a floor pulled from the air. A shrinking executable set is a
    # silent reduction in coverage, so changing this number is a deliberate act.
    assert len(EXECUTABLE) == EXPECTED_EXECUTABLE, (
        f"{len(EXECUTABLE)} of {len(CASES)} cases are executable here, expected "
        f"{EXPECTED_EXECUTABLE}; update EXPECTED_EXECUTABLE deliberately"
    )


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


@pytest.mark.parametrize("case", EVALUATED_CASES, ids=lambda c: c.case_id[:48])
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


def test_there_are_cases_of_both_kinds():
    """If either list were empty the split would hide a whole family."""
    assert EVALUATED_CASES, "no evaluated cases"
    assert NOT_EVALUATED_CASES, "no not-evaluated cases; the exclusion attaches to nothing"
    assert len(EVALUATED_CASES) + len(NOT_EVALUATED_CASES) == len(EXECUTABLE)


@pytest.mark.parametrize("case", NOT_EVALUATED_CASES, ids=lambda c: c.case_id[:48])
def test_a_not_evaluated_case_is_insensitive_to_its_planted_value(case):
    """The fact that makes the ordinary declared-component check inapplicable.

    MCPValidationDetector reads `function.name` and nothing else, so a canary
    in a description or a parameter schema is never evaluated. Running the same
    case with two entirely different planted values must produce the identical
    observed component -- which is precisely why passing the ordinary check
    would have proved nothing about the planted value.
    """
    manifest_case = MANIFEST_CASES[case.case_id]

    one = execute(manifest_case, case.canary)
    two = execute(manifest_case, "TOTALLY-DIFFERENT-VALUE-9a3f")

    assert one.components, diagnose(case, "no component was reached at all")
    assert one.components == two.components, diagnose(
        case, f"the planted value changed the component: {one.components} vs {two.components}"
    )


@pytest.mark.parametrize("case", NOT_EVALUATED_CASES, ids=lambda c: c.case_id[:48])
def test_a_not_evaluated_case_records_why(case):
    reason = is_not_evaluated(MANIFEST_CASES[case.case_id])
    assert reason and "function.name" in reason


def test_an_evaluated_case_IS_sensitive_to_its_planted_value():
    """The control on the split.

    If evaluated cases were also insensitive to their planted value, the
    not-evaluated test above would be asserting nothing special. Same case,
    two values, and the observed component must differ.
    """
    from tests.release.execution import EVENT_FOR
    from tests.release.observation import all_regions, observing

    case = next(c for c in EVALUATED_CASES if c.detector == "emoji")
    manifest_case = MANIFEST_CASES[case.case_id]

    from app.scanner_engine import ScannerEngine

    def components(text: str) -> set[str]:
        engine = ScannerEngine.from_detectors({manifest_case.detector: {"enabled": True}})
        event = EVENT_FOR.get(manifest_case.detector, manifest_case.event)
        with observing() as observation:
            engine.scan(text, event_type=event, vault_id="v", vault=None)
        return observation.components(all_regions())

    with_emoji = components("value \U0001f600")
    without = components("value with no emoji at all")

    assert with_emoji != without, (
        "the emoji detector reported the same component for a value with an "
        "emoji and one without, so evaluated cases are insensitive too"
    )
    assert "emoji/reported" in with_emoji
    assert "emoji/reported" not in without


# --- the representation axis is DRIVEN, not merely labelled -----------------


@pytest.mark.parametrize("family", [f.name for f in FAMILIES], ids=lambda n: n)
def test_each_representation_family_has_cases_and_is_driven(family: str):
    """The manifest's seven-fold multiplicity must be exercised, not accepted.

    Every representation case previously ran identical plain text: the value
    was encoded nowhere and the family used only to label a signature.
    """
    cases = [c for c in EXECUTABLE if c.representation == family]
    assert cases, f"no executable case declares representation {family}"

    case = cases[0]
    execution = execute(MANIFEST_CASES[case.case_id], case.canary)
    assert execution.wire, "nothing was placed on the wire"
    assert execution.planted, "nothing was handed to the boundary"


@pytest.mark.parametrize("family", [f.name for f in FAMILIES], ids=lambda n: n)
def test_the_wire_form_round_trips_through_its_own_decoder(family: str):
    """A decoder that is not an inverse silently changes the planted value.

    `\\uXXXX` escaping emitted five hex digits for astral codepoints, so the
    form was malformed and did not round-trip at all.
    """
    from tests.release.representations import decode

    value = "CANARY-café-\U0001f600-9f"
    wire = encode_for(family, value)
    assert decode(family, wire) == value


@pytest.mark.parametrize("family", [f.name for f in FAMILIES if f.name not in ("plain", "raw-bytes", "nfc")])
def test_a_family_whose_wire_form_differs_is_actually_transformed(family: str):
    """The control on the drive.

    If encode_for returned its input for every family, the tests above would
    pass while nothing was encoded. Six of seven families are byte-identical
    for ASCII, so this uses a value where they must differ.
    """
    value = "CANARY-café-\U0001f600-9f"
    assert encode_for(family, value) != value, f"{family} did not transform the value"


def test_the_boundary_decode_is_what_the_detector_sees():
    """Not the wire form.

    A detector matching emoji codepoints correctly fails to match the ASCII
    text `\\ud83d\\ude00`, so handing it the escaped form would make every
    escaped emoji case observe the wrong state -- which is what happened
    before the decode step existed.
    """
    case = next(c for c in EXECUTABLE if c.representation == "unicode-escaped" and c.detector == "emoji")
    execution = execute(MANIFEST_CASES[case.case_id], case.canary)

    assert (
        execution.wire != execution.planted
    ), "the wire and boundary forms are identical, so the decode is untested here"
    assert (
        execution.received[0] == execution.planted
    ), "the detector received the wire form rather than the decoded value"
