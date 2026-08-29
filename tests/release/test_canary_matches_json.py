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
def test_the_canary_should_reach_matches_json_and_does_not(case, family, tmp_path):
    """One record per case and representation, through production's channel
    AND production's persistence.

    Two things this got wrong first, both of which made the signature a label
    rather than an observation:

      * it encoded with `manifest_case.representation` instead of the
        parametrised `family`, so each case executed its OWN representation
        seven identical times while claiming seven different ones -- the
        round-2 finding, reproduced exactly;
      * it serialised the collector in the test and inspected that string, so
        the signatures named collector `database` and surface
        `interactions.matches_json` while never touching either. Removing
        production's assignment of captured_matches to the stored row would
        not have changed the answer.
    """
    from app.scanner_engine import ScannerEngine
    from tests.release.execution import decode_at_boundary, encode_for
    from tests.release.leaves import captured_value, detector_config, shape
    from tests.release.persistence import capture_matches_into

    manifest_case = MANIFEST_CASES[case.case_id]
    plain = shape(manifest_case.leaf, case.canary, manifest_case.sub_path)
    # THE PARAMETRISED FAMILY drives the encoding, not the case's own.
    text = decode_at_boundary(family, encode_for(family, plain))

    messages = [{"role": "user", "content": text}]
    collector = _build_collector(messages)
    # The config the detector needs to actually fire. `custom_entity` matches
    # nothing without a pattern, so a bare {"enabled": True} had 98 of these
    # cases asserting the capture of a value nothing had detected.
    engine = ScannerEngine.from_detectors(
        {manifest_case.detector: detector_config(manifest_case.detector, case.canary)}
    )
    engine.scan(
        text,
        event_type=manifest_case.event,
        vault_id="v",
        vault=None,
        tools=None,
        messages=messages,
        matches=collector,
    )

    captured = {
        "schema_version": 1,
        "matches": [g.as_storable() for g in collector.finalize()],
    }
    # Read back FROM SQLITE, through build_content + capture_content.
    stored = capture_matches_into(tmp_path / "store.db", matches=captured, canary=case.canary)

    # What capture SHOULD hold is the value the DETECTOR matched, which is only
    # the canary when the canary is inside that value. For `card` and `ssn` the
    # canary is planted alongside on purpose, so asserting on it asked capture
    # to contain a string the detector never saw -- unsatisfiable however
    # correct capture is, and what 91 of these cases were failing on.
    expected = decode_at_boundary(family, encode_for(family, captured_value(manifest_case.leaf, case.canary)))
    if expected.lower() not in stored.lower():
        RECORDER.record_and_fail(
            Signature(
                case_id=f"{case.case_id}#matches_json",
                property=REQUIRED_MISSING,
                collector="database",
                surface_path=SURFACE,
                representation=family,
                occurrence_rule="REQUIRED",
            ),
            diagnose(case, f"matches_json holds no occurrence of {expected!r}: {stored[:120]}"),
        )


def test_the_collector_finalises_with_the_match_for_a_real_detection():
    """The measurement behind all 245, stated once and directly.

    It used to assert ZERO groups, and left a tripwire saying that if a detector
    ever did report through this channel the 245 records should be reconsidered.
    The tripwire fired: a detector named itself by its class while the scanner
    opened its capture batch under the policy's key for it, the mismatch failed
    staging, and every batch was poisoned at debug level. Fixed by taking the
    name from the batch.

    So this now asserts the opposite, which is the point of having written it
    as a premise rather than as a constant.
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

    groups = collector.finalize()
    assert groups, "the detector found a value and the collector finalised empty"
    stored = [g.as_storable() for g in groups]
    assert any("canary.person@example.com" in str(g.get("value")) for g in stored), stored
    # The name the POLICY knows it by, which is the half that was wrong.
    assert all(g["detector"] == "confidential_and_pii_entity" for g in stored), stored


def test_the_parametrised_family_genuinely_changes_the_planted_input():
    """The drive is real even though the OUTCOME cannot discriminate.

    An absence property is insensitive to the decoder by construction: the
    canary is missing from matches_json whether or not the percent decoder
    works, so "break one family's decoder and require only its cases to
    change" cannot be satisfied here and pretending otherwise would be the
    defect this programme removes.

    What CAN be established is that the parametrised family drives the input
    rather than labelling it -- which is what was wrong before, when every case
    executed its own representation seven times under seven different labels.
    """
    from tests.release.execution import decode_at_boundary, encode_for
    from tests.release.leaves import captured_value, detector_config, shape

    case = CASES[0]
    manifest_case = MANIFEST_CASES[case.case_id]
    plain = shape(manifest_case.leaf, case.canary, manifest_case.sub_path)

    wire = {f.name: encode_for(f.name, plain) for f in FAMILIES}
    assert len(set(wire.values())) > 1, (
        f"every family produced identical wire bytes for {plain!r}, so the "
        "parametrisation cannot be shown to drive anything"
    )

    # And each round-trips to the same boundary value, which is why the
    # detector sees the same input and the outcome is uniform.
    decoded = {name: decode_at_boundary(name, w) for name, w in wire.items()}
    assert set(decoded.values()) == {plain}, decoded


def test_a_broken_decoder_is_caught_where_an_outcome_can_see_it():
    """Not here -- but not nowhere.

    The representation drive is mutation-tested against the capture-off suite,
    whose outcome DOES depend on the decoded value. Recorded here so the
    insensitivity above is not mistaken for the decoders being untested.
    """
    import pathlib

    source = (pathlib.Path(__file__).resolve().parent / "test_canary_capture_off.py").read_text()
    assert "test_the_boundary_decode_is_what_the_detector_sees" in source
    assert "test_the_wire_form_round_trips_through_its_own_decoder" in source
