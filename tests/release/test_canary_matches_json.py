"""The matches_json family: a REQUIRED occurrence that never happens.

The manifest predicts 245 records -- 35 capture-on cases x 7 representations --
each asserting the canary SHOULD reach `interactions.matches_json` and does
not. This drives them through production's own exact-match channel.

WHY THE VALUE IS REQUIRED THERE: capture-on means the operator asked for the
evidence. A stored interaction whose matches are empty records that something
was detected without recording what, which is the difference between an audit
trail and a count.

WHY IT DOES NOT HAPPEN, in production's own words (app/routes/guard.py):
"Exact matches await the detector wiring: the typed channel from step 1 exists
but no detector reports through it yet". The collector is built, passed to
`engine.scan`, and finalised into `matches_json` -- and finalises empty.

This is a REQUIRED-occurrence failure, the direction an emitted-only suite
structurally cannot see: nothing is emitted, so nothing is routed, so nothing
is unresolved.
"""

from __future__ import annotations

import json
import warnings

import pytest

from app.routes.guard import _build_collector
from tests.release.canary_suite import cases_for, diagnose
from tests.release.execution import is_not_evaluated
from tests.release.manifest import EXACT_MATCH_DETECTORS, load_cases
from tests.release.representations import FAMILIES
from tests.release.signatures import RECORDER, Signature

warnings.filterwarnings("ignore")

MANIFEST_CASES = {c.identity: c for c in load_cases()}

#: Mirrors `expected_failures.matches_json_records` exactly, so the signatures
#: this suite emits line up with the records the manifest predicts. A different
#: selection here would produce novel signatures the gate would reject.
#: Marker observability is NOT required here -- this family's property is
#: whether the value reaches matches_json, which needs the detector and the
#: collector, not the line trace. `custom_entity` carries no markers and runs
#: perfectly well, so excluding it on marker grounds would have left 91 of the
#: manifest's own records permanently unoccurred for an irrelevant reason.
CASES = [
    c
    for c in cases_for("capture-on")
    if c.detector in EXACT_MATCH_DETECTORS and not is_not_evaluated(MANIFEST_CASES[c.case_id])
]

SURFACE = "interactions.matches_json"
REQUIRED_MISSING = "REQUIRED occurrence was never emitted"


def test_the_selection_matches_the_manifests_own():
    """If these diverged, this suite would emit signatures the gate calls
    novel while the manifest's own records went on never occurring."""
    from tests.release.expected_failures import matches_json_records

    predicted = {r.case_id for r in matches_json_records(load_cases())}
    ours = {f"{c.case_id}#matches_json" for c in CASES}
    assert ours == predicted, {
        "predicted, not driven": sorted(predicted - ours)[:2],
        "driven, not predicted": sorted(ours - predicted)[:2],
    }


def test_there_are_cases_to_drive():
    assert CASES, "no capture-on exact-match case is executable here"


def test_the_collector_channel_exists_in_production():
    """The premise. If the channel were absent, "it stays empty" would be a
    statement about nothing."""
    import pathlib

    source = pathlib.Path("app/routes/guard.py").read_text()
    assert "_build_collector" in source
    assert "match_collector" in source
    assert "matches" in source


#: The manifest generates SEVEN records per case -- one per representation
#: family -- so the drive is parametrised over the PAIR. Parametrising over
#: cases alone emitted 35 signatures against 245 predicted records, and the
#: gate would have reported 210 as never occurring.
DRIVES = [(c, f.name) for c in CASES for f in FAMILIES]


@pytest.mark.parametrize(("case", "family"), DRIVES, ids=lambda v: (v.case_id[:36] if hasattr(v, "case_id") else v))
def test_the_canary_should_reach_matches_json_and_does_not(case, family):
    """One record per case and representation, through production's channel."""
    from app.scanner_engine import ScannerEngine
    from tests.release.execution import decode_at_boundary, encode_for
    from tests.release.leaves import shape

    manifest_case = MANIFEST_CASES[case.case_id]
    plain = shape(manifest_case.leaf, case.canary, manifest_case.sub_path)
    text = decode_at_boundary(manifest_case.representation, encode_for(manifest_case.representation, plain))

    messages = [{"role": "user", "content": text}]
    collector = _build_collector(messages)
    engine = ScannerEngine.from_detectors({manifest_case.detector: {"enabled": True}})
    engine.scan(
        text,
        event_type=manifest_case.event,
        vault_id="v",
        vault=None,
        tools=None,
        messages=messages,
        matches=collector,
    )

    stored = json.dumps({"schema_version": 1, "matches": [g.as_storable() for g in collector.finalize()]})

    if case.canary.lower() not in stored.lower():
        RECORDER.record_and_fail(
            Signature(
                case_id=f"{case.case_id}#matches_json",
                property=REQUIRED_MISSING,
                collector="database",
                surface_path=SURFACE,
                representation=family,
                occurrence_rule="REQUIRED",
            ),
            diagnose(case, f"matches_json holds no occurrence of the canary: {stored[:120]}"),
        )


def test_the_collector_finalises_empty_for_a_real_detection():
    """The measurement behind all 245, stated once and directly.

    A real PII value, a real collector, the real engine: zero groups.
    """
    from app.scanner_engine import ScannerEngine

    text = "contact canary.person@example.com about it"
    collector = _build_collector([{"role": "user", "content": text}])
    engine = ScannerEngine.from_detectors({"confidential_and_pii_entity": {"enabled": True}})
    engine.scan(
        text,
        event_type="input",
        vault_id="v",
        vault=None,
        tools=None,
        messages=[{"role": "user", "content": text}],
        matches=collector,
    )

    assert collector.finalize() == [], (
        "premise changed: a detector now reports through the exact-match "
        "channel, so these 245 records should be reconsidered"
    )
