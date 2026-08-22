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
    EVENTS,
    LEAVES,
    NOT_EVALUATED,
    PLACEMENTS,
    REPRESENTATIONS,
    CaptureMode,
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


# --- oracle 1: source components vs manifest components --------------------


def test_every_source_component_is_exercised_by_a_case():
    """Produced vs declared, in the direction that catches source drift.

    A component that exists in `app/` and appears in no case is a path the
    suite never reaches. The eighteen secrets plugins are data-declared and
    exercised through their detector, so they map to it rather than each
    needing a case.
    """
    from_source = {c.identity for c in inventory.scan_source()}
    exercised = {f"{c.component}/{c.sub_path}" for c in CASES}
    plugin_components = {i for i in from_source if i.startswith("secrets/")}
    unreached = from_source - exercised - plugin_components
    assert unreached == set(), sorted(unreached)


def test_every_secrets_plugin_is_registered_individually():
    """Eighteen entries, not one `plugin_set` identity.

    Collapsing them meant deleting `TwilioKeyDetector` left the rendered
    artifact byte-identical and every test green.
    """
    plugins = {i for i in inventory.load_generated() if i.startswith("secrets/")}
    assert len(plugins) == 18, sorted(plugins)


# --- oracle 2: the canonical leaf/placement domain vs the cases ------------


def test_every_declared_leaf_and_placement_pair_has_a_case():
    """The relation, not a Cartesian product.

    A bare product would demand nonsensical pairs like
    `policy-name@tool-parameters`; `APPLICABLE` is the canonical relation and
    this compares the cases against it in both directions.
    """
    declared = {(leaf, placement) for leaf, places in APPLICABLE.items() for placement in places}
    produced = {(c.leaf, c.placement) for c in CASES}
    assert produced == declared, {
        "declared but no case": sorted(declared - produced),
        "case but not declared": sorted(produced - declared),
    }


def test_every_leaf_is_in_the_applicability_relation():
    assert set(APPLICABLE) == set(LEAVES)
    for places in APPLICABLE.values():
        assert set(places) <= set(PLACEMENTS)


# --- oracle 3: every other axis -------------------------------------------
#
# The gap the first version left entirely: branch, detector, event, capture,
# representation and collector coverage can all drift while the source
# components and the leaf/placement projection stay identical. Deleting `nfd`
# and `browser-network` was already a false green with no case rows at all.


@pytest.mark.parametrize(
    "name,declared,observed",
    [
        ("branch", lambda: set(BRANCHES), lambda: {c.branch for c in CASES}),
        ("detector", lambda: set(DETECTORS), lambda: {c.detector for c in CASES} - {"none"}),
        ("event", lambda: set(EVENTS), lambda: {c.event for c in CASES}),
        ("representation", lambda: set(REPRESENTATIONS), lambda: {c.representation for c in CASES}),
        ("capture", lambda: {m.value for m in CaptureMode}, lambda: {c.capture.value for c in CASES}),
        (
            "collector",
            lambda: set(COLLECTORS),
            lambda: {col for c in CASES for col in c.collectors},
        ),
    ],
)
def test_every_declared_axis_value_is_covered_by_a_case(name, declared, observed):
    d, o = declared(), observed()
    assert o == d, {"declared, no case": sorted(d - o), "in a case, not declared": sorted(o - d)}


def test_the_collector_set_is_part_of_case_identity():
    """Two rows differing only by a dropped collector must not share an identity.

    Omitting collectors from the identity meant a case that silently stopped
    sweeping the database, a log selector or transport looked unchanged.
    """
    case = CASES[0]
    thinner = type(case)(**{**case.__dict__, "collectors": case.collectors[:-1]})
    assert thinner.identity != case.identity


def test_not_evaluated_is_keyed_by_component_not_only_leaf():
    """The fact is about a component not reading a leaf.

    Keyed by leaf alone it would still look true if some other component began
    evaluating MCP descriptions tomorrow.
    """
    assert set(NOT_EVALUATED) == {
        ("mcp-description", "mcp_validation", "scan"),
        ("mcp-parameters", "mcp_validation", "scan"),
    }
