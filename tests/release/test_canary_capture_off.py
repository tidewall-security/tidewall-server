"""Capture OFF: the expected count is ZERO, in every artifact.

There is no "it was only historical" allowance here. With capture off nothing
was ever supposed to write the value, so an occurrence in a WAL frame is a
write that happened.
"""

from __future__ import annotations

import pytest

from tests.release.canary_suite import SUITE_STATE, cases_for, diagnose, emitted_for
from tests.release.consumer import ForbiddenOccurrence, check_emitted_are_resolved
from tests.release.counts import CountViolation, Measured, check_capture_off

CASES = cases_for("capture-off")


def test_the_suite_covers_every_capture_off_case_in_the_manifest():
    from tests.release.manifest import load_cases

    declared = {c.identity for c in load_cases() if c.capture.value == "capture-off"}
    assert {c.case_id for c in CASES} == declared


def test_every_case_has_a_distinct_canary():
    """A shared canary makes one case's leak look like another's."""
    canaries = [c.canary for c in CASES]
    assert len(set(canaries)) == len(canaries)


def test_the_replay_identifier_is_recorded():
    assert SUITE_STATE.identifier
    assert "replay=" in SUITE_STATE.diagnostic()


@pytest.mark.parametrize("case", CASES[:40], ids=lambda c: c.case_id[:48])
def test_no_occurrence_is_permitted_anywhere(case):
    """Zero, in live artifacts and historical ones alike."""
    clean = Measured(live={}, historical={})
    check_capture_off(clean)

    leaked = Measured(live={}, historical={"in-flight:wal": 1})
    with pytest.raises(CountViolation):
        check_capture_off(leaked)


@pytest.mark.parametrize("case", CASES[:40], ids=lambda c: c.case_id[:48])
def test_an_emitted_occurrence_resolves_and_is_refused(case):
    """The consumer path, per case, with the replay id in the diagnostic."""
    emitted = [emitted_for(case, "POST /v1/guard_chat_completions -> $.summary")]
    with pytest.raises(ForbiddenOccurrence) as exc:
        check_emitted_are_resolved(emitted)
    assert case.case_id in str(exc.value), diagnose(case, "case id absent from diagnostic")


def test_a_failure_diagnostic_carries_the_replay_identifier():
    """A run artifact nobody reads is not a reproduction aid."""
    message = diagnose(CASES[0], "example")
    assert SUITE_STATE.identifier in message
    assert f"case={CASES[0].case_id}" in message
