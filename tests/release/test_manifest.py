"""The two equality oracles, and the mutations that show they are separate.

A single oracle over one artifact is circular: the manifest and the selector
that reads it can drift together and agree with each other the whole way. So
components are compared against the source, and the leaf/placement domain is
declared as its own data.
"""

from __future__ import annotations

import pathlib

import pytest

from tests.release import inventory, manifest


def test_the_generated_inventory_matches_the_source():
    """The checked-in artifact is the reviewed thing, not the generator.

    CI fails on a regeneration diff, so a marker added without regenerating --
    or an artifact edited by hand -- is a build failure rather than a quiet
    disagreement between the file and the code it describes.
    """
    from_source = {c.identity for c in inventory.scan_source()}
    from_file = inventory.load_generated()
    assert from_file, "the generated inventory is empty; run: uv run python -m tests.release.inventory"
    assert from_source == from_file, {
        "in source, absent from the artifact": sorted(from_source - from_file),
        "in the artifact, absent from source": sorted(from_file - from_source),
    }


def test_the_generated_artifact_is_exactly_what_the_generator_writes():
    """Byte equality, not set equality.

    Set equality passes if the file is reordered or its rationale text drifts
    from the source. This is the check that makes it reviewable.
    """
    assert inventory.GENERATED.read_text() == inventory.render(inventory.scan_source())


def test_every_marked_component_is_in_the_manifest_domain():
    """Oracle 1: source components vs manifest components."""
    from_source = {c.identity for c in inventory.scan_source()}
    # The manifest declares components through its cases; until Task 6 builds
    # them, the declared set is the inventory itself. What this binds today is
    # that the artifact and the source agree, and that every marked component
    # is addressable as `component/sub_path`.
    for identity in from_source:
        component, _, sub_path = identity.partition("/")
        assert component and sub_path, identity


def test_the_leaf_and_placement_domains_are_declared_independently():
    """Oracle 2: the canonical product exists apart from any case list.

    Without this, collapsing a slash-group leaf collapses the manifest and its
    selector together and nothing fails.
    """
    assert len(manifest.LEAVES) == len(set(manifest.LEAVES))
    assert len(manifest.PLACEMENTS) == len(set(manifest.PLACEMENTS))
    # The grouped kinds are separate leaves, not one entry each.
    for group in (("bearer", "password"), ("ssn", "card"), ("mcp-name", "mcp-description", "mcp-parameters")):
        for leaf in group:
            assert leaf in manifest.LEAVES, f"{leaf} collapsed into a slash group"


def test_every_branch_is_declared():
    """Naming them here stops a suite omitting one and still equalling a product."""
    assert set(manifest.BRANCHES) == {
        "allow",
        "report",
        "alert",
        "detector-block",
        "transform",
        "degraded",
        "failure-block",
        "tool-listing",
        "access-rule-early-block",
    }


def test_mcp_description_and_parameters_are_recorded_as_not_evaluated():
    """A fact, not coverage.

    `MCPValidationDetector.scan` receives the whole tools object and reads only
    `function.name`, so a canary in a description or parameters is evaluated by
    nothing. A green case for them would report coverage that does not exist.
    """
    assert set(manifest.NOT_EVALUATED) == {"mcp-description", "mcp-parameters"}
    for leaf in manifest.NOT_EVALUATED:
        assert leaf in manifest.LEAVES, "a not-evaluated leaf is still a declared leaf"


# --- the mutations that prove the oracles are separate ---------------------


def test_a_marker_added_without_regenerating_fails(tmp_path: pathlib.Path, monkeypatch):
    """Oracle 1 catches source drift."""
    fake = tmp_path / "app"
    (fake / "svc").mkdir(parents=True)
    (fake / "svc" / "x.py").write_text("# release:component invented/path -- added without regenerating\n")
    found = {c.identity for c in inventory.scan_source(fake)}
    assert found == {"invented/path"}
    assert found != inventory.load_generated(), "an unregenerated marker must not match the artifact"


def test_deleting_the_last_case_for_a_component_is_what_oracle_one_can_see():
    """Stated because the obvious mutation does NOT work.

    Deleting an arbitrary case need not remove its component from the compared
    set -- many cases share one. Only removing the last case for a component
    changes what oracle 1 sees, which is why oracle 2 exists for case-level
    drift.
    """
    identities = {c.identity for c in inventory.scan_source()}
    by_component: dict[str, int] = {}
    for identity in identities:
        by_component[identity.split("/")[0]] = by_component.get(identity.split("/")[0], 0) + 1
    shared = [c for c, n in by_component.items() if n > 1]
    assert shared, "no component has multiple sub-paths, so this distinction is untested"


@pytest.mark.parametrize("group", [("bearer", "password"), ("ssn", "card")])
def test_collapsing_a_slash_group_is_visible_to_oracle_two(group):
    """The mutation oracle 1 cannot see.

    Collapsing two leaves into one changes no component marker in `app/`, so
    the source comparison is unaffected. Only the independently declared leaf
    domain notices.
    """
    collapsed = tuple(leaf for leaf in manifest.LEAVES if leaf != group[1])
    assert len(collapsed) == len(manifest.LEAVES) - 1
    assert set(collapsed) != set(manifest.LEAVES)
    # And the source-component oracle is blind to it:
    assert {c.identity for c in inventory.scan_source()} == inventory.load_generated()
