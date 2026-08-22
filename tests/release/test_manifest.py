"""Three equality oracles over the execution manifest.

The first version of this file declared domains and asserted things about the
domains. It compared no manifest to anything, and three separate drifts passed
all ten of its tests. These oracles each compare something produced against
something declared, and each test states which drift it can see -- because the
useful question about an oracle is not what it checks but what it CANNOT.
"""

from __future__ import annotations

import pathlib

import pytest

from tests.release import inventory
from tests.release.manifest import (
    APPLICABLE,
    BRANCHES,
    CASES,
    COLLECTORS,
    DETECTORS,
    EVENT_SCOPED,
    EVENTS,
    EXACT_MATCH_DETECTORS,
    GRANTS,
    LEAVES,
    NOT_EVALUATED,
    OPERATIONS,
    PLACEMENTS,
    REPRESENTATIONS,
    CaptureMode,
    registry_detectors,
    report_match_callers,
    source_event_scoping,
)

# --- the generated artifact -----------------------------------------------


def test_the_generated_inventory_matches_the_source():
    from_source = {c.identity for c in inventory.scan_source()}
    from_file = inventory.load_generated()
    assert from_file, "empty; run: uv run python -m tests.release.inventory"
    assert from_source == from_file, {
        "in source, absent from artifact": sorted(from_source - from_file),
        "in artifact, absent from source": sorted(from_file - from_source),
    }


def test_the_generated_artifact_is_byte_identical_to_what_the_generator_writes():
    assert inventory.GENERATED.read_text() == inventory.render(inventory.scan_source())


def test_a_marker_inside_a_string_literal_is_not_a_declaration(tmp_path: pathlib.Path):
    """Tokenised, not pattern-matched over raw lines.

    A regex over lines registered `string_literal/not_a_comment` from an
    ordinary assignment, so a dead string could satisfy the source oracle with
    no declaration comment anywhere.
    """
    (tmp_path / "m.py").write_text(
        'x = "# release:component fake/one -- in a string"\n' "# release:component real/two -- an actual comment\n"
    )
    found = {c.identity for c in inventory.scan_source(tmp_path)}
    assert found == {"real/two"}


def test_a_duplicate_identity_is_rejected(tmp_path: pathlib.Path):
    """Two sites claiming one identity collapse to one in any set comparison."""
    (tmp_path / "a.py").write_text("# release:component dup/one -- first site\n")
    (tmp_path / "b.py").write_text("# release:component dup/one -- second site\n")
    with pytest.raises(inventory.DuplicateComponent):
        inventory.scan_source(tmp_path)


def test_a_marker_without_a_rationale_is_not_a_declaration(tmp_path: pathlib.Path):
    (tmp_path / "m.py").write_text("# release:component bare/marker\n")
    assert inventory.scan_source(tmp_path) == []


# --- the oracles, now comparing against checked-in DATA -------------------
#
# The previous version generated the cases from the same domains it then
# compared them against, so every comparison was equality by construction:
# deleting `nfd` removed it from the declared set and from every case at once,
# and all seventeen tests passed. The cases now live in a file no generator
# writes, so a domain edit does not move them.


def test_source_components_and_exercised_components_are_equal():
    """Actually both directions.

    The previous version said "both directions" in its docstring and asserted
    only `exercised <= from_source`. On the shipped branch that left FIFTEEN
    marked components unexercised while every test passed -- every secrets
    plugin except the three a case happened to name.
    """
    from_source = {c.identity for c in inventory.scan_source()}
    exercised = {f"{c.component}/{c.sub_path}" for c in CASES}
    assert exercised == from_source, {
        "in source, no case exercises it": sorted(from_source - exercised),
        "named by a case, no source marker": sorted(exercised - from_source),
    }


def test_every_secrets_plugin_is_registered_individually():
    plugins = {i for i in inventory.load_generated() if i.startswith("secrets/")}
    assert len(plugins) == 18, sorted(plugins)


def test_no_case_pairs_an_event_scoped_detector_with_the_wrong_event():
    """Production scoping, not the manifest's opinion of it.

    `malicious_entity` runs only for `output` and `mcp_validation` only for
    `tool_listing` (`_detector_applies`). A row pairing either with another
    event describes a path that cannot execute -- 56 such rows shipped in the
    generated version.
    """
    for case in CASES:
        scoped = EVENT_SCOPED.get(case.detector)
        if scoped:
            assert case.event == scoped, f"{case.detector} is {scoped}-scoped: {case.identity}"


def test_matches_json_is_only_required_where_a_detector_reports_exact_values():
    """Only PII and custom-entity call report_match.

    A classifier's DetectorResult has no source/value field, so requiring its
    canary in matches_json manufactures a failure for correct behaviour.
    """
    assert EXACT_MATCH_DETECTORS == {"confidential_and_pii_entity", "custom_entity"}


@pytest.mark.parametrize(
    "name,declared,observed",
    [
        ("leaf", lambda: set(LEAVES), lambda: {c.leaf for c in CASES}),
        ("placement", lambda: set(PLACEMENTS), lambda: {c.placement for c in CASES}),
        ("branch", lambda: set(BRANCHES), lambda: {c.branch for c in CASES}),
        ("detector", lambda: set(DETECTORS), lambda: {c.detector for c in CASES} - {"none"}),
        ("event", lambda: set(EVENTS), lambda: {c.event for c in CASES}),
        ("representation", lambda: set(REPRESENTATIONS), lambda: {c.representation for c in CASES}),
        ("capture", lambda: {m.value for m in CaptureMode}, lambda: {c.capture.value for c in CASES}),
        ("collector", lambda: set(COLLECTORS), lambda: {x for c in CASES for x in c.collectors}),
    ],
)
def test_every_declared_axis_value_appears_in_the_checked_in_cases(name, declared, observed):
    """Independent, because the cases are data.

    Deleting `nfd` from REPRESENTATIONS now fails: the constant loses it and
    the 64 checked-in rows carrying it do not.
    """
    d, o = declared(), observed()
    assert o == d, {"declared, in no case": sorted(d - o), "in a case, not declared": sorted(o - d)}


def test_the_relation_and_the_cases_agree_in_both_directions():
    """One-way was not enough.

    Checking only "every case is applicable" let the relation shrink without
    failing: collapsing `bearer` to a single placement removed a pair no case
    happened to use, and every test passed. A declared pair with no case is a
    gap in coverage, and a case outside the relation is a nonsensical pair --
    both must fail.
    """
    declared = {(leaf, place) for leaf, places in APPLICABLE.items() for place in places}
    produced = {(c.leaf, c.placement) for c in CASES}
    assert produced == declared, {
        "declared, no case exercises it": sorted(declared - produced),
        "a case uses it, not declared": sorted(produced - declared),
    }


def test_the_collector_set_is_part_of_case_identity():
    case = CASES[0]
    thinner = type(case)(**{**case.__dict__, "collectors": case.collectors[:-1]})
    assert thinner.identity != case.identity


def test_not_evaluated_is_keyed_by_component_not_only_leaf():
    assert set(NOT_EVALUATED) == {
        ("mcp-description", "mcp_validation", "scan"),
        ("mcp-parameters", "mcp_validation", "scan"),
    }


# --- production facts, read from source rather than trusted ---------------


def test_the_exact_match_detector_constant_matches_production():
    """Wiring a third detector to report_match must fail this.

    The constant was a hand-copied measurement, and the previous test compared
    it to the same hardcoded pair -- so a production change could not fail it.
    """
    assert EXACT_MATCH_DETECTORS == report_match_callers()


def test_the_detector_domain_matches_the_production_registry():
    assert set(DETECTORS) == set(registry_detectors())


def test_the_event_scoping_constant_matches_production():
    assert EVENT_SCOPED == source_event_scoping()


def test_every_case_operation_and_grant_is_declared():
    """Both are in Case.identity and neither had a domain.

    An invented operation passed all twenty tests before this.
    """
    assert {c.operation for c in CASES} <= set(OPERATIONS)
    assert {c.grant for c in CASES} <= set(GRANTS)
    assert set(OPERATIONS) == {c.operation for c in CASES}
    assert set(GRANTS) == {c.grant for c in CASES}
