"""Applying the derivation rule to real states."""

from __future__ import annotations

import warnings

import pytest

from tests.release.observation import all_regions, observing
from tests.release.states import (
    NotBehaviourChanging,
    StatesNotDistinct,
    Surface,
    derive,
)

warnings.filterwarnings("ignore")


def _run(config: dict, text: str, event: str = "input"):
    from app.scanner_engine import ScannerEngine

    engine = ScannerEngine.from_detectors(config)
    with observing() as obs:
        result = engine.scan(text, event_type=event, vault_id="v", vault=None)
    return obs.components(all_regions()), result


# --- the rule itself --------------------------------------------------------


def test_a_state_that_alters_no_surface_field_is_refused():
    """Marking a location does not make it a behaviour-changing state."""

    class R:
        blocked = False
        transformed = False
        guard_output_text = "same"
        detectors = ()
        summary_parts = ()
        failures = ()
        partial = False

    with pytest.raises(NotBehaviourChanging, match="altered no surface field"):
        derive(state="x/y", with_state=({"x/y"}, R()), without_state=(set(), R()))


def test_two_runs_that_did_not_differ_in_the_state_are_refused():
    """Otherwise any surface difference is credited to the wrong cause."""
    with pytest.raises(StatesNotDistinct, match="not reached by the run"):
        derive(state="x/y", with_state=(set(), object()), without_state=(set(), object()))

    with pytest.raises(StatesNotDistinct, match="reached by the control run too"):
        derive(state="x/y", with_state=({"x/y"}, object()), without_state=({"x/y"}, object()))


def test_the_surface_covers_every_field_a_caller_sees():
    import dataclasses

    from app.scanner_engine import ScanResult
    from tests.release.states import SURFACE_FIELDS

    fields = {f.name for f in dataclasses.fields(ScanResult)}
    assert set(SURFACE_FIELDS) == fields, {
        "in ScanResult, not compared": sorted(fields - set(SURFACE_FIELDS)),
        "compared, not in ScanResult": sorted(set(SURFACE_FIELDS) - fields),
    }


# --- derived states ---------------------------------------------------------


def test_emoji_reported_is_behaviour_changing():
    """Same detector, same code path; one input reaches the state."""
    found = _run({"emoji": {"enabled": True}}, "hi \U0001f600")
    none = _run({"emoji": {"enabled": True}}, "no emoji here at all")

    diff = derive(state="emoji/reported", with_state=found, without_state=none)
    assert diff, "no surface field differed"


def test_pii_entities_redacted_is_behaviour_changing():
    found = _run({"confidential_and_pii_entity": {"enabled": True}}, "email a@b.com")
    none = _run({"confidential_and_pii_entity": {"enabled": True}}, "nothing of interest")

    diff = derive(state="pii/entities_redacted", with_state=found, without_state=none)
    assert diff


def test_pii_no_entities_is_behaviour_changing():
    """The other side of the same pair.

    Stated separately because a state is not behaviour-changing merely
    because its complement is.
    """
    none = _run({"confidential_and_pii_entity": {"enabled": True}}, "nothing of interest")
    found = _run({"confidential_and_pii_entity": {"enabled": True}}, "email a@b.com")

    diff = derive(state="pii/no_entities", with_state=none, without_state=found)
    assert diff


def test_scanner_engine_applicability_skip_is_NOT_behaviour_changing():
    """A DERIVED result, and not the one assumed.

    Skipping a detector as inapplicable produces a ScanResult identical in
    every field to not having configured it: nothing is blocked differently,
    no failure is recorded, no summary part appears. On this evidence the
    state does not change behaviour.

    It stays a marked location -- coverage still wants to know the branch was
    taken -- but it does NOT belong in the behaviour-changing state domain,
    and asserting that it does would have been an assumption dressed as a
    measurement.
    """
    skipped = _run({"emoji": {"enabled": True}, "malicious_entity": {"enabled": True}}, "hi \U0001f600")
    not_skipped = _run({"emoji": {"enabled": True}}, "hi \U0001f600")

    assert "scanner_engine/applicability_skip" in skipped[0]
    assert "scanner_engine/applicability_skip" not in not_skipped[0]

    with pytest.raises(NotBehaviourChanging):
        derive(
            state="scanner_engine/applicability_skip",
            with_state=skipped,
            without_state=not_skipped,
        )


def test_mcp_name_similarity_is_behaviour_changing():
    """Event-scoped: reached for tool_listing, skipped for input."""
    listing = _run({"mcp_validation": {"enabled": True}}, "tools", event="tool_listing")
    other = _run({"mcp_validation": {"enabled": True}}, "tools", event="input")

    diff = derive(state="mcp_validation/name_similarity", with_state=listing, without_state=other)
    assert diff


def test_a_surface_comparison_that_looks_at_nothing_finds_no_difference():
    """The control on the rule.

    If SURFACE_FIELDS were empty, every state would be declared inert. This
    fixes the direction of the evidence: differences come from the fields, not
    from the pair being different.
    """
    found = _run({"emoji": {"enabled": True}}, "hi \U0001f600")
    none = _run({"emoji": {"enabled": True}}, "no emoji here at all")

    a, b = Surface.of(found[1]), Surface.of(none[1])
    assert a.differences(b), "the two runs produced identical surfaces"
    assert set(a.differences(b)) <= set(Surface.of(found[1]).values)
