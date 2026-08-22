"""Step 1a: verify Task 2's declared components against observed execution.

Task 2 could not do this. Every one of its oracles compares one declaration
with another, and a review demonstrated the gap by rewriting a case's
component with all twenty tests still green.

These tests RUN the detector and watch which marked regions execute. Each
known-suspect mapping named in the plan is settled here, with a control
proving the mechanism can see the marker it reports as unreached -- otherwise
"not reached" is indistinguishable from "not visible in this environment".
"""

from __future__ import annotations

import warnings

import pytest

from tests.release.manifest import load_cases
from tests.release.observation import all_regions, observing

warnings.filterwarnings("ignore")


def _reached(detector: str, text: str, event_type: str) -> set[str]:
    from app.scanner_engine import ScannerEngine

    engine = ScannerEngine.from_detectors({detector: {"enabled": True}})
    with observing() as obs:
        engine.scan(text, event_type=event_type, vault_id="v", vault=None)
    return obs.components(all_regions())


def _declared_for(branch: str, detector: str) -> set[str]:
    return {f"{c.component}/{c.sub_path}" for c in load_cases() if c.branch == branch and c.detector == detector}


# --- the control, first -----------------------------------------------------


def test_the_mechanism_discriminates_a_taken_branch_from_an_untaken_one():
    """Without this, every 'not reached' below is indistinguishable from
    'not visible in this environment'."""
    present = _reached("emoji", "hi \U0001f600", "input")
    absent = _reached("emoji", "no emoji here at all", "input")
    assert "emoji/reported" in present
    assert "emoji/reported" not in absent


def test_the_topic_markers_are_reachable_when_the_topic_detector_runs():
    """Both topic pipelines, with topics configured.

    Reported unconditionally before the marker regions were narrowed to the
    branch bodies they guard.
    """
    from app.scanner_engine import ScannerEngine

    engine = ScannerEngine.from_detectors({"topic": {"enabled": True, "topics": ["politics", "violence"]}})
    with observing() as obs:
        engine.scan("let us discuss politics", event_type="input", vault_id="v", vault=None)
    reached = obs.components(all_regions())

    assert "topic/topics_pipeline" in reached, sorted(reached)
    assert "topic/toxicity_pipeline" in reached, sorted(reached)


# --- the five suspect mappings ----------------------------------------------


@pytest.mark.parametrize(
    ("branch", "detector", "text"),
    [
        ("allow", "code", "def f():\n    return 1\n"),
        ("allow", "language", "bonjour le monde"),
        ("report", "emoji", "hello \U0001f600 \U0001f4a9"),
    ],
)
def test_a_case_reaches_the_component_it_declares(branch: str, detector: str, text: str):
    """Rejects a case whose declared component is not the one it reaches.

    All three declared a component belonging to a DIFFERENT detector --
    `allow/code` claimed `topic/topics_pipeline`, `allow/language` claimed
    `topic/toxicity_pipeline`, `report/emoji` claimed
    `malicious_prompt/app_intent` -- and none of those detectors carried a
    marker at all. Corrected to the components they were observed to reach.
    """
    declared = _declared_for(branch, detector)
    assert declared, f"no manifest case for {branch}/{detector}"
    reached = _reached(detector, text, "input")

    unreached = declared - reached
    assert not unreached, f"{branch}/{detector} declares {sorted(unreached)}, observed {sorted(reached)}"


def test_the_pii_transform_rows_reach_the_component_they_declare():
    """The fourth wrong mapping.

    These rows declared `scanner_engine/degraded`, and it appeared to hold --
    but only because the marker sat on an `if` and was credited whenever the
    check ran. With the region narrowed to the guarded body, the PII detector
    reaches no scanner_engine marker at all.
    """
    declared = _declared_for("transform", "confidential_and_pii_entity")
    assert declared == {"pii/entities_redacted"}, declared
    reached = _reached("confidential_and_pii_entity", "email a@b.com ssn 123-45-6789", "input")
    assert declared <= reached, sorted(reached)


def test_the_pii_detector_distinguishes_finding_entities_from_finding_none():
    clean = _reached("confidential_and_pii_entity", "nothing of interest here", "input")
    assert "pii/no_entities" in clean, sorted(clean)
    assert "pii/entities_redacted" not in clean, sorted(clean)


def test_mcp_validation_is_reached_only_for_the_tool_listing_event():
    """It is event-scoped. Observing it under `input` reports applicability_skip."""
    declared = _declared_for("tool-listing", "mcp_validation")
    assert declared == {"mcp_validation/name_similarity"}, declared

    listing = _reached("mcp_validation", "list tools", "tool_listing")
    assert "mcp_validation/name_similarity" in listing, sorted(listing)

    inp = _reached("mcp_validation", "list tools", "input")
    assert "mcp_validation/name_similarity" not in inp, sorted(inp)


def test_mcp_validation_never_evaluates_a_description_or_parameters():
    """Confirms the plan's suspicion behaviourally, not by reading the marker.

    The detector reads `function.name` and nothing else, so a canary in a
    description or a parameter schema is never evaluated -- and a case whose
    leaf is `mcp-description` or `mcp-parameters` cannot honestly claim this
    component evaluated it.
    """
    from app.detectors.mcp_validation import MCPValidationDetector

    detector = MCPValidationDetector({"enabled": True})

    def tools(desc_a: str, desc_b: str, name_a: str = "get_user", name_b: str = "get_users"):
        return [
            {"function": {"name": name_a, "description": desc_a, "parameters": {"p": desc_a}}},
            {"function": {"name": name_b, "description": desc_b, "parameters": {"p": desc_b}}},
        ]

    plain = detector.scan("", tools=tools("harmless", "harmless"))
    canaried = detector.scan("", tools=tools("CANARY-MCP-DESC", "CANARY-MCP-DESC"))

    assert plain.detected == canaried.detected, "changing only the description changed the verdict, so it IS evaluated"
    assert "CANARY-MCP-DESC" not in str(canaried.data), "the canary reached the detector's own output"

    # The control: changing the NAME does change the verdict, so the detector
    # is not simply inert.
    distinct = detector.scan("", tools=tools("harmless", "harmless", "alpha", "zulu_completely_other"))
    assert distinct.detected != plain.detected, (
        "the name change did not alter the verdict either, so this test "
        "cannot distinguish 'not evaluated' from 'detector does nothing'"
    )
