"""The mechanism that can tell a declared component from a reached one."""

from __future__ import annotations

import pytest

from tests.release.inventory import APP, scan_source
from tests.release.observation import (
    ComponentMismatch,
    NoRegion,
    all_regions,
    observing,
    region_for,
    verify_declared_component,
)

# --- regions ----------------------------------------------------------------


def test_every_marker_in_the_source_has_a_region():
    """A marker introducing no statement can never be observed.

    It would sit in the inventory forever, be named by cases, and reach
    nothing.
    """
    regions = all_regions()
    assert len(regions) == len(scan_source()), "a marker was lost mapping to regions"


def test_a_region_begins_after_its_marker():
    """A comment never executes. A region containing only the marker line
    observes nothing, ever."""
    for component in scan_source():
        region = region_for(component)
        assert region.start > component.line, (
            f"{component.identity}: region starts at {region.start}, " f"marker is at {component.line}"
        )


def test_regions_are_bounded_not_the_rest_of_the_file():
    """'Any line after the marker' credits every marker below the first hit."""
    regions = all_regions()
    unbounded = [r.identity for r in regions.values() if r.end - r.start > 200]
    assert not unbounded, f"suspiciously large marked regions: {unbounded}"


def test_a_marker_introducing_no_statement_is_refused(tmp_path):
    from tests.release.inventory import Component

    src = tmp_path / "app" / "m.py"
    src.parent.mkdir(parents=True)
    src.write_text("x = 1\n# release:component a/b -- trailing, nothing follows\n")
    c = Component(component="a", sub_path="b", source="app/m.py", line=2, why="trailing")
    with pytest.raises(NoRegion, match="introduces no statement"):
        region_for(c, root=tmp_path / "app")


# --- observation ------------------------------------------------------------


def test_observation_records_only_lines_under_the_root(tmp_path):
    """Tracing everything drowns the result in library frames."""
    with observing(root=APP) as obs:
        "".join(str(i) for i in range(3))  # stdlib work, not app work
    assert all(f.startswith(str(APP.resolve())) for f in obs.lines), sorted(obs.lines)


def test_a_reached_marker_is_observed_and_an_unreached_one_is_not(tmp_path):
    """The whole point, on a synthetic module with two markers."""
    root = tmp_path / "app"
    root.mkdir()
    (root / "__init__.py").write_text("")
    (root / "two.py").write_text(
        "def taken():\n"
        "    # release:component alpha/taken -- the branch under test\n"
        "    return 'alpha'\n"
        "\n"
        "def skipped():\n"
        "    # release:component beta/skipped -- never called\n"
        "    return 'beta'\n"
    )

    import importlib.util

    spec = importlib.util.spec_from_file_location("two_mod", root / "two.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    regions = {c.identity: region_for(c, root) for c in scan_source(root)}
    assert set(regions) == {"alpha/taken", "beta/skipped"}

    with observing(root=root) as obs:
        module.taken()

    reached = obs.components(regions, root=root)
    assert reached == {"alpha/taken"}, f"observed {reached}; beta/skipped was never called and must not appear"


def test_observing_a_real_scan_reports_the_components_it_actually_reached():
    """Against production source, not a fixture.

    The emoji detector is used because it is pure Python: it reaches its
    markers in any environment, so a failure here is a failure of the
    mechanism rather than of model availability.
    """
    from app.scanner_engine import ScannerEngine

    regions = all_regions()
    engine = ScannerEngine.from_detectors({"emoji": {"enabled": True}})

    with observing() as obs:
        engine.scan("hi \U0001f600", event_type="input", vault_id="v", vault=None)

    reached = obs.components(regions)
    assert "emoji/pattern_match" in reached, sorted(reached)
    assert "emoji/reported" in reached, sorted(reached)


def test_a_marker_on_a_branch_test_is_narrowed_to_the_branch_body():
    """The imprecision that made every observation mean 'the check ran'.

    A marker above `if cond:` was credited whenever the CHECK executed,
    whatever branch was taken. Nineteen of the source's markers had that
    shape, so `scanner_engine/applicability_skip` was reported by every scan
    -- including single-detector runs where nothing was ever skipped.

    Same detector, same code path, two inputs: the emoji branch is taken for
    one and not the other.
    """
    from app.scanner_engine import ScannerEngine

    regions = all_regions()

    def reached(text: str) -> set[str]:
        engine = ScannerEngine.from_detectors({"emoji": {"enabled": True}})
        with observing() as obs:
            engine.scan(text, event_type="input", vault_id="v", vault=None)
        return obs.components(regions)

    with_emoji = reached("hi \U0001f600")
    without = reached("no emoji here at all")

    assert (
        "emoji/pattern_match" in with_emoji and "emoji/pattern_match" in without
    ), "the pattern runs either way, so this marker should appear in both"
    assert "emoji/reported" in with_emoji
    assert "emoji/reported" not in without, "a marker inside a branch was reported although the branch was not taken"


def test_applicability_skip_is_reported_only_when_a_detector_is_skipped():
    """The marker that used to fire on every run."""
    from app.scanner_engine import ScannerEngine

    regions = all_regions()

    def reached(config: dict) -> set[str]:
        engine = ScannerEngine.from_detectors(config)
        with observing() as obs:
            engine.scan("hi \U0001f600", event_type="input", vault_id="v", vault=None)
        return obs.components(regions)

    # malicious_entity is output-only, so on an input event it IS skipped.
    with_skip = reached({"emoji": {"enabled": True}, "malicious_entity": {"enabled": True}})
    without_skip = reached({"emoji": {"enabled": True}})

    assert "scanner_engine/applicability_skip" in with_skip
    assert (
        "scanner_engine/applicability_skip" not in without_skip
    ), "reported as skipped although every configured detector applied"


def test_a_component_no_scan_touches_is_not_reported():
    """The control. Without it, a mechanism that reports every known marker
    would satisfy the test above.
    """
    from app.scanner_engine import ScannerEngine

    regions = all_regions()
    engine = ScannerEngine.from_detectors({"malicious_prompt": {"enabled": True}})

    with observing() as obs:
        engine.scan("hello", event_type="input", vault_id="v", vault=None)

    reached = obs.components(regions)
    assert reached, "nothing was observed at all, so absence proves nothing here"
    assert reached < set(regions), (
        "every marked component in the source was reported as reached by a "
        "single scan, which means the mechanism is not discriminating"
    )


# --- the rejection rule -----------------------------------------------------


def test_a_case_declaring_a_component_it_reached_is_accepted():
    verify_declared_component("case-1", "alpha/taken", {"alpha/taken", "other/x"})


def test_a_case_declaring_a_component_it_did_not_reach_is_rejected():
    """The exact substitution the review demonstrated."""
    with pytest.raises(ComponentMismatch, match="topic/topics_pipeline"):
        verify_declared_component("case-1", "topic/topics_pipeline", {"malicious_prompt/generic_injection_ml"})


def test_a_case_that_reached_no_marked_component_says_so():
    """Distinct from reaching the wrong one, and a different thing to fix."""
    with pytest.raises(ComponentMismatch, match="no marked component at all"):
        verify_declared_component("case-1", "malicious_prompt/generic_injection_ml", set())
