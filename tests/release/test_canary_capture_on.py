"""Capture ON: EXACT cardinality against the canonical live image.

Not "at least one". A unique column holds its value twice, so both an
under-count and an over-count are failures, and the image must be rebuilt or
the count measures page churn.
"""

from __future__ import annotations

import sqlite3

import pytest

from tests.release.canary_suite import SUITE_STATE, cases_for, diagnose, emitted_for
from tests.release.consumer import RequiredOccurrenceMissing, check_required_are_emitted
from tests.release.counts import CountViolation, check_capture_on

CASES = cases_for("capture-on")


def _schema() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE policies (id INTEGER PRIMARY KEY, name TEXT UNIQUE)")
    return conn


def test_the_suite_covers_every_capture_on_case_in_the_manifest():
    from tests.release.manifest import load_cases

    declared = {c.identity for c in load_cases() if c.capture.value == "capture-on"}
    assert {c.case_id for c in CASES} == declared


def test_every_case_has_a_distinct_canary():
    canaries = [c.canary for c in CASES]
    assert len(set(canaries)) == len(canaries)


def test_the_exact_copy_map_count_is_required():
    conn = _schema()
    check_capture_on(conn, ("policies", "name"), canonical_count=2)
    conn.close()


@pytest.mark.parametrize("wrong", [1, 3])
def test_an_inexact_count_fails(wrong: int):
    conn = _schema()
    with pytest.raises(CountViolation):
        check_capture_on(conn, ("policies", "name"), canonical_count=wrong)
    conn.close()


@pytest.mark.parametrize("case", CASES[:40], ids=lambda c: c.case_id[:48])
def test_a_required_occurrence_that_is_never_emitted_fails(case):
    """The direction an emitted-only suite structurally cannot see."""
    required = [emitted_for(case, "interactions.matches_json")]
    with pytest.raises(RequiredOccurrenceMissing) as exc:
        check_required_are_emitted(emitted=[], required=required)
    assert case.case_id in str(exc.value), diagnose(case, "case id absent from diagnostic")


@pytest.mark.parametrize("case", CASES[:40], ids=lambda c: c.case_id[:48])
def test_a_required_occurrence_that_is_emitted_passes(case):
    required = [emitted_for(case, "interactions.matches_json")]
    check_required_are_emitted(emitted=list(required), required=required)


def test_a_failure_diagnostic_carries_the_replay_identifier():
    message = diagnose(CASES[0], "example")
    assert SUITE_STATE.identifier in message
    assert f"case={CASES[0].case_id}" in message
