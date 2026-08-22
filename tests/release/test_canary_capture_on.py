"""Capture ON, driven through PRODUCTION.

EXACT cardinality against the canonical live image -- not "at least one". A
unique column holds its value twice, so both an under-count and an over-count
are failures, and the image must be rebuilt or the count measures page churn.

Like the capture-off suite, this drove nothing before: it asserted its case
list matched the manifest and then checked hand-built objects. Every assertion
below runs the real engine.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from tests.release.attribution import expected_locations
from tests.release.canary_suite import SUITE_STATE, cases_for, diagnose
from tests.release.counts import CountViolation, canonical_live_image, check_capture_on
from tests.release.execution import SELF_CONTAINED_DETECTORS, chain_for, execute, witnesses_for
from tests.release.manifest import load_cases
from tests.release.observation import verify_declared_component
from tests.release.signatures import RECORDER, Signature
from tests.release.witnesses import AbsenceEvaluator, assert_absent

CASES = cases_for("capture-on")
MANIFEST_CASES = {c.identity: c for c in load_cases()}
EXECUTABLE = [c for c in CASES if c.detector in SELF_CONTAINED_DETECTORS]

#: Measured, and pinned so a shrinking set is visible rather than silent.
EXPECTED_EXECUTABLE = 49


def test_the_suite_covers_every_capture_on_case_in_the_manifest():
    declared = {c.identity for c in load_cases() if c.capture.value == "capture-on"}
    assert {c.case_id for c in CASES} == declared


def test_every_case_has_a_distinct_canary():
    canaries = [c.canary for c in CASES]
    assert len(set(canaries)) == len(canaries)


def test_some_cases_are_executable_here():
    """If none were, every execution test below would vacuously pass."""
    assert EXECUTABLE, "no capture-on case can run in this environment"


def test_the_unexecutable_cases_are_reported_rather_than_counted_as_passes():
    unexecutable = [c for c in CASES if c.detector not in SELF_CONTAINED_DETECTORS]
    assert len(EXECUTABLE) + len(unexecutable) == len(CASES)
    # PINNED, not a floor pulled from the air. A shrinking executable set is a
    # silent reduction in coverage, so changing this number is a deliberate act.
    assert len(EXECUTABLE) == EXPECTED_EXECUTABLE, (
        f"{len(EXECUTABLE)} of {len(CASES)} cases are executable here, expected "
        f"{EXPECTED_EXECUTABLE}; update EXPECTED_EXECUTABLE deliberately"
    )


@pytest.mark.parametrize("case", EXECUTABLE, ids=lambda c: c.case_id[:48])
def test_the_case_runs_and_reaches_the_component_it_declares(case):
    """The check absence properties structurally cannot make."""
    manifest_case = MANIFEST_CASES[case.case_id]
    execution = execute(manifest_case, case.canary)
    declared = f"{manifest_case.component}/{manifest_case.sub_path}"

    assert execution.received, diagnose(case, "the detector received nothing")
    verify_declared_component(diagnose(case, declared), declared, execution.components)


@pytest.mark.parametrize("case", EXECUTABLE, ids=lambda c: c.case_id[:48])
def test_absence_is_asserted_only_behind_a_complete_witness(case):
    manifest_case = MANIFEST_CASES[case.case_id]
    execution = execute(manifest_case, case.canary)

    ingress, outcome, collector = witnesses_for(execution, store_rows=1)
    chain = chain_for(execution, manifest_case)
    chain = type(chain)(**{**chain.__dict__, "component": execution.detector})

    evaluator = AbsenceEvaluator()
    found = execution.occurrences_of(case.canary)
    for surface, _count in sorted(found.items()):
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

    assert_absent(
        chain,
        ingress=ingress,
        outcome=outcome,
        collector=collector,
        declared_object_count=len(execution.surfaces()),
        found=bool(found),
        evaluator=evaluator,
    )
    assert evaluator.called_for(case.case_id)


# --- exact cardinality against a rebuilt image ------------------------------


def _store(tmp_path: Path) -> Path:
    db = tmp_path / "store.db"
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE policies (id INTEGER PRIMARY KEY, name TEXT UNIQUE)")
    conn.commit()
    conn.close()
    return db


def test_the_exact_copy_map_count_is_required_against_real_bytes(tmp_path: Path):
    """Measured on the rebuilt image, not a supplied number.

    A unique column's value is on disk twice -- table B-tree and index -- so a
    check expecting one occurrence fails against working code.
    """
    db = _store(tmp_path)
    canary = b"CANARY-CAPTURE-ON-2f71"

    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO policies(id, name) VALUES (1, ?)", (canary.decode(),))
    conn.commit()
    conn.close()

    image = canonical_live_image(db, tmp_path / "canonical" / "image.db")
    actual = image.read_bytes().count(canary)

    conn = sqlite3.connect(db)
    try:
        predicted = sum(expected_locations(conn, ("policies", "name")).values())
        assert actual == predicted, f"image holds {actual}, copy map predicts {predicted}"
        check_capture_on(conn, ("policies", "name"), canonical_count=actual)
    finally:
        conn.close()


@pytest.mark.parametrize("delta", [-1, 1])
def test_an_inexact_count_fails(tmp_path: Path, delta: int):
    db = _store(tmp_path)
    conn = sqlite3.connect(db)
    try:
        predicted = sum(expected_locations(conn, ("policies", "name")).values())
        with pytest.raises(CountViolation):
            check_capture_on(conn, ("policies", "name"), canonical_count=predicted + delta)
    finally:
        conn.close()


def test_a_failure_diagnostic_carries_the_replay_identifier():
    message = diagnose(CASES[0], "example")
    assert SUITE_STATE.identifier in message
    assert f"case={CASES[0].case_id}" in message
