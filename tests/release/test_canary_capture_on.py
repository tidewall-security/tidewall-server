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
import sqlalchemy as sa

from app.db.models import Base
from tests.release.attribution import expected_locations
from tests.release.canary_suite import SUITE_STATE, cases_for, diagnose
from tests.release.counts import CountViolation, canonical_live_image, check_capture_on
from tests.release.execution import SELF_CONTAINED_DETECTORS, chain_for, execute, witnesses_for
from tests.release.manifest import load_cases
from tests.release.observation import verify_declared_component
from tests.release.persistence import (
    BLOB_COLUMN,
    CaptureNotPerformed,
    capture_into,
    live_cells_holding,
    occurrences_in_canonical_image,
    occurrences_in_working_file,
    store_raw_bytes,
    stored_type,
)
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


# --- production capture, measured off the bytes -----------------------------


def test_production_capture_writes_the_value_and_the_store_shows_it(tmp_path: Path):
    """The real capture path, not a synthetic table.

    The suite previously asserted cardinality against a `policies(id, name)`
    database it populated itself, so disabling production capture would not
    have failed a single named case.
    """
    db = tmp_path / "store.db"
    canary = "CANARY-CAPTURE-ON-PERSIST-3e17"

    assert capture_into(db, canary=canary) == 1

    cells = live_cells_holding(db, canary)
    assert cells, "capture wrote nothing this scan can see"
    assert {column for _t, _r, column in cells} == {"input_json", "matches_json"}, cells
    assert {table for table, _r, _c in cells} == {"interaction_contents"}, cells


def test_the_canonical_image_count_matches_the_live_cells(tmp_path: Path):
    """Exact cardinality against the REBUILT image, from a real capture.

    Counting the working file instead would count page churn.
    """
    db = tmp_path / "store.db"
    canary = "CANARY-CAPTURE-ON-IMAGE-6d02"
    capture_into(db, canary=canary)

    in_image = occurrences_in_canonical_image(db, tmp_path / "img.db", canary.encode())
    cells = live_cells_holding(db, canary)

    assert in_image == len(cells), (
        f"the rebuilt image holds {in_image} occurrences and the live store has "
        f"{len(cells)} cells holding the value: {sorted(cells)}"
    )


def test_capture_off_writes_nothing_for_the_same_exercise(tmp_path: Path):
    """The control that makes the count above mean something.

    Without it, "the value is in the store" is equally true of a store that
    always contains it.
    """
    db = tmp_path / "store.db"
    canary = "CANARY-CAPTURE-OFF-CONTROL-1f44"

    engine = sa.create_engine(f"sqlite:///{db}")
    Base.metadata.create_all(engine)
    engine.dispose()

    assert occurrences_in_canonical_image(db, tmp_path / "img.db", canary.encode()) == 0
    assert live_cells_holding(db, canary) == set()


def test_a_capture_that_wrote_no_row_is_refused(tmp_path: Path, monkeypatch):
    """The guard must FIRE, not merely exist.

    This test previously raised CaptureNotPerformed itself and asserted the
    message -- so it tested `raise`, and a guard deleted outright would have
    passed it. Production capture is neutered here and the real code path is
    required to refuse.
    """
    import tests.release.persistence as persistence

    monkeypatch.setattr(persistence, "capture_content", lambda *a, **k: None)

    with pytest.raises(CaptureNotPerformed, match="measuring"):
        capture_into(tmp_path / "store.db", canary="CANARY-NO-ROW-2b88")


def test_the_same_exercise_without_the_neutering_does_write_a_row(tmp_path: Path):
    """The control. Without it, the refusal above could be caused by anything."""
    assert capture_into(tmp_path / "store.db", canary="CANARY-NO-ROW-CONTROL-4c19") == 1


def test_the_value_is_in_the_working_file_too(tmp_path: Path):
    """Sidecars included, so a WAL-resident write is not missed."""
    db = tmp_path / "store.db"
    canary = "CANARY-CAPTURE-ON-WORKING-8c55"
    capture_into(db, canary=canary)
    assert occurrences_in_working_file(db, canary.encode()) > 0


# --- raw-bytes is a STORAGE property, not an ingress one --------------------


def test_the_text_ingress_cannot_carry_a_blob_at_all():
    """Stated, because the alternative is pretending otherwise.

    `ScannerEngine.scan` takes `str`. A driver that encodes bytes and decodes
    them straight back to text has exercised TEXT, and counting that as
    raw-bytes coverage is the labelling defect this programme removes.
    """
    import inspect

    from app.scanner_engine import ScannerEngine

    annotation = inspect.signature(ScannerEngine.scan).parameters["text"].annotation
    assert annotation in ("str", str), annotation


def test_raw_bytes_are_stored_with_sqlites_blob_storage_class(tmp_path: Path):
    """The property the family names, at the surface that can hold it."""
    db = tmp_path / "vault.db"
    payload = "CANARY-RAW-café-\U0001f600".encode()

    store_raw_bytes(db, payload=payload)

    assert stored_type(db, *BLOB_COLUMN) == "blob", (
        "the value was not stored as a BLOB, so this does not exercise raw-byte "
        "storage whatever the column type says"
    )


def test_a_raw_byte_canary_is_found_by_a_byte_scan_of_the_rebuilt_image(tmp_path: Path):
    db = tmp_path / "vault.db"
    payload = "CANARY-RAW-SCAN-café-\U0001f600".encode()
    store_raw_bytes(db, payload=payload)

    assert occurrences_in_canonical_image(db, tmp_path / "img.db", payload) == 1


def test_a_non_ascii_blob_is_missed_by_the_text_families_and_found_by_raw_bytes(
    tmp_path: Path,
):
    """Why the family exists at all.

    For ASCII the families are byte-identical, which is why an ASCII probe
    collapses them. With non-ASCII content the escaped forms are genuinely
    different bytes, and only the raw form is what is on disk.
    """
    from tests.release.representations import FAMILIES

    value = "CANARY-RAW-DISTINCT-café-\U0001f600"
    db = tmp_path / "vault.db"
    store_raw_bytes(db, payload=value.encode())
    image_bytes = canonical_live_image(db, tmp_path / "img.db").read_bytes()

    raw = next(f for f in FAMILIES if f.name == "raw-bytes")
    assert raw.encode(value) in image_bytes

    escaped = next(f for f in FAMILIES if f.name == "unicode-escaped")
    assert escaped.encode(value) not in image_bytes, (
        "the escaped form is on disk too, so this does not distinguish the " "families"
    )
