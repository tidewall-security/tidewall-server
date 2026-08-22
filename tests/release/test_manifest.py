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
    OPERATION_GRANT,
    OPERATIONS,
    PLACEMENT_OPERATIONS,
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


def test_the_component_state_domain_is_recorded_as_deferred():
    """The plan requires states; the registry has component names.

    Distinct from the mapping deferral: that asks whether a case reaches the
    component it names, this asks whether the component's state domain exists
    at all. Neither is established here, and both are Task 5's.
    """
    from tests.release import manifest

    assert manifest.STATE_DOMAIN_DEFERRED_TO_TASK_5 is False
    assert manifest.STATE_DOMAIN_DERIVED_IN == "tests/release/test_states.py"
    assert manifest.BEHAVIOUR_CHANGING_STATES, "the derived domain is empty"
    # The derived NEGATIVE is part of the result, not an omission from it.
    assert "scanner_engine/applicability_skip" in manifest.MARKED_LOCATIONS_NOT_STATES
    assert not (manifest.BEHAVIOUR_CHANGING_STATES & manifest.MARKED_LOCATIONS_NOT_STATES)


def test_the_component_mapping_is_recorded_as_unverified():
    """What this module can and cannot establish.

    A case naming a component is not evidence that it reaches one. Verifying
    that requires observing execution, which is Task 5's instrumentation, so
    the claim is recorded as deferred rather than defended by oracles that
    cannot see it. This test exists so removing that acknowledgement fails.
    """
    from tests.release import manifest

    assert manifest.VERIFICATION_DEFERRED_TO_TASK_5 is False
    assert manifest.COMPONENT_MAPPING_VERIFIED_IN == "tests/release/test_component_mapping.py"
    assert pathlib.Path(manifest.COMPONENT_MAPPING_VERIFIED_IN).exists()


def test_source_components_and_exercised_components_are_named_by_a_case():
    """Named by a case -- NOT reached by one.

    Actually both directions.

    The previous version said "both directions" in its docstring and asserted
    only `exercised <= from_source`. On the shipped branch that left FIFTEEN
    marked components unexercised while every test passed -- every secrets
    plugin except the three a case happened to name.
    """
    from_source = {c.identity for c in inventory.scan_source()}
    named = {f"{c.component}/{c.sub_path}" for c in CASES}
    assert named == from_source, {
        "in source, named by no case": sorted(from_source - named),
        "named by a case, no source marker": sorted(named - from_source),
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
    for leaf, component, sub_path in NOT_EVALUATED:
        assert leaf and component and sub_path


def test_every_not_evaluated_key_matches_a_real_case():
    """The property that catches a mis-keyed exclusion.

    These were keyed to sub-path "scan" -- the method name -- while every
    manifest case declares "name_similarity". The exclusion attached to
    nothing, and the cases went through the ordinary declared-component and
    evaluated-input checks as though the value had been evaluated. Comparing
    the keys to a hardcoded pair could not notice, because the pair was the
    same hardcoded thing.
    """
    keys = {(c.leaf, c.component, c.sub_path) for c in CASES}
    unattached = sorted(set(NOT_EVALUATED) - keys)
    assert not unattached, unattached


def test_the_not_evaluated_leaves_are_the_ones_production_ignores():
    """Read from the detector, not from this module's opinion of it."""
    source = pathlib.Path("app/detectors/mcp_validation.py").read_text()
    assert 'func.get("name"' in source
    assert 'func.get("description"' not in source
    assert 'func.get("parameters"' not in source

    excluded_leaves = {leaf for leaf, _c, _s in NOT_EVALUATED}
    assert excluded_leaves == {"mcp-description", "mcp-parameters"}


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


def test_every_case_binds_its_operation_to_its_placement_and_grant():
    """The RELATION, not marginal set membership.

    Set equality left a row free to swap `guard`/`api` for the equally
    declared `policy-admin`/`admin` even where that operation cannot invoke the
    named detector. Both halves must hold per case.
    """
    for case in CASES:
        assert case.operation in OPERATIONS, case.identity
        assert case.grant in GRANTS, case.identity
        assert OPERATION_GRANT[case.operation] == case.grant, (
            f"{case.identity}: {case.operation} requires " f"{OPERATION_GRANT[case.operation]}, not {case.grant}"
        )
        assert (
            case.operation in PLACEMENT_OPERATIONS[case.placement]
        ), f"{case.identity}: {case.placement} cannot be reached by {case.operation}"


def test_the_operation_and_grant_domains_are_fully_exercised():
    """Equality, not containment.

    `<=` passed with two of seven operations and two of five grants absent --
    the protected reads were declared in the constants and used by no case, so
    Task 3's read rows were unreachable from Task 2 and no later consumer could
    exercise them without inventing an undeclared case.
    """
    assert {c.operation for c in CASES} == set(OPERATIONS), {
        "declared, no case": sorted(set(OPERATIONS) - {c.operation for c in CASES})
    }
    assert {c.grant for c in CASES} == set(GRANTS), {
        "declared, no case": sorted(set(GRANTS) - {c.grant for c in CASES})
    }


def test_a_decoy_class_cannot_satisfy_the_report_match_check(tmp_path, monkeypatch):
    """Exercises `report_match_callers()` itself, not a helper it happens to use.

    The first version called `_calls_any()` directly on synthetic AST nodes and
    never invoked the function under test at all -- so the round-5 mutant
    (crediting any class in the module) would have passed it. This points the
    real function at a fake tree and asserts the registered class is what
    decides.
    """
    from tests.release import manifest

    root = tmp_path
    (root / "app").mkdir()
    (root / "app" / "scanner_engine.py").write_text(
        "_DETECTOR_REGISTRY: dict = {\n" '    "fake_detector": ("app.detectors.fake", "Registered"),\n' "}\n"
    )
    (root / "app" / "detectors").mkdir()
    (root / "app" / "detectors" / "fake.py").write_text(
        "def _report_match(*a, **k):\n"
        "    report_match(*a, **k)\n"
        "\n"
        "class Registered:\n"
        "    def scan(self):\n"
        "        return None\n"
        "\n"
        "class Decoy:\n"
        "    def scan(self):\n"
        "        _report_match(1)\n"
    )
    monkeypatch.setattr(manifest, "__file__", str(root / "tests" / "release" / "manifest.py"))
    (root / "tests" / "release").mkdir(parents=True)

    assert manifest.report_match_callers() == frozenset(), (
        "the decoy calls the wrapper and the REGISTERED class does not; "
        "crediting the detector would be the round-5 defect"
    )


def test_the_registered_class_is_credited_when_it_does_call(tmp_path, monkeypatch):
    """The other direction, so the check is not simply always-empty."""
    from tests.release import manifest

    root = tmp_path
    (root / "app").mkdir()
    (root / "app" / "scanner_engine.py").write_text(
        "_DETECTOR_REGISTRY: dict = {\n" '    "fake_detector": ("app.detectors.fake", "Registered"),\n' "}\n"
    )
    (root / "app" / "detectors").mkdir()
    (root / "app" / "detectors" / "fake.py").write_text(
        "def _report_match(*a, **k):\n"
        "    report_match(*a, **k)\n"
        "\n"
        "class Registered:\n"
        "    def scan(self):\n"
        "        _report_match(1)\n"
    )
    (root / "tests" / "release").mkdir(parents=True)
    monkeypatch.setattr(manifest, "__file__", str(root / "tests" / "release" / "manifest.py"))

    assert manifest.report_match_callers() == frozenset({"fake_detector"})
