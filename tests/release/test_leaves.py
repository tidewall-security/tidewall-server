"""Leaf shaping, and the ways it could make an assertion vacuous."""

from __future__ import annotations

import warnings

import pytest

from tests.release.canary_suite import cases_for
from tests.release.execution import SELF_CONTAINED_DETECTORS, execute
from tests.release.leaves import NEGATIVE_STATES, NoShapeForLeaf, shape, tools_for
from tests.release.manifest import load_cases

warnings.filterwarnings("ignore")

CANARY = "CANARY-LEAF-7b2c"
MANIFEST_CASES = {c.identity: c for c in load_cases()}
EXECUTABLE_LEAVES = sorted({c.leaf for c in cases_for("capture-off") if c.detector in SELF_CONTAINED_DETECTORS})


@pytest.mark.parametrize("leaf", EXECUTABLE_LEAVES)
def test_every_executable_leaf_has_a_shape(leaf: str):
    assert shape(leaf, CANARY)


@pytest.mark.parametrize("leaf", EXECUTABLE_LEAVES)
def test_every_shape_embeds_the_canary(leaf: str):
    """A shape that dropped the canary would make every leak anonymous."""
    assert CANARY.lower() in shape(leaf, CANARY).lower()


@pytest.mark.parametrize("leaf", EXECUTABLE_LEAVES)
def test_the_negative_form_also_embeds_the_canary(leaf: str):
    assert CANARY.lower() in shape(leaf, CANARY, "no_entities").lower()


def test_an_unknown_leaf_is_refused_rather_than_defaulted():
    """A default shape would drive the case with a value the detector ignores,
    and the case would observe a found-nothing state while declaring
    otherwise."""
    with pytest.raises(NoShapeForLeaf, match="no shaping rule"):
        shape("not-a-leaf", CANARY)


def test_a_negative_state_is_shaped_differently_from_a_positive_one():
    assert shape("random-canary", CANARY, "pattern_match") != shape("random-canary", CANARY)
    assert shape("email", CANARY, "no_entities") != shape("email", CANARY)


def test_the_negative_form_carries_nothing_a_detector_matches():
    text = shape("email", CANARY, "no_entities")
    assert "@" not in text
    assert not any(ch.isdigit() for ch in text.replace(CANARY, ""))


@pytest.mark.parametrize("state", sorted(NEGATIVE_STATES))
def test_negative_states_are_the_found_nothing_ones(state: str):
    assert state in {"pattern_match", "no_entities"}


# --- the distinction the shaping exists to make -----------------------------


def test_a_pattern_match_case_does_not_also_reach_reported():
    """Without state-aware shaping the emoji case reached BOTH states, so the
    declared-component check passed for a case declaring either one."""
    case = next(c for c in cases_for("capture-off") if MANIFEST_CASES[c.case_id].sub_path == "pattern_match")
    observed = execute(MANIFEST_CASES[case.case_id], case.canary).components
    assert "emoji/pattern_match" in observed
    assert "emoji/reported" not in observed, observed


def test_a_reported_case_reaches_both_which_is_correct():
    """Reporting implies the pattern ran; the converse is what must not hold."""
    case = next(c for c in cases_for("capture-off") if MANIFEST_CASES[c.case_id].sub_path == "reported")
    observed = execute(MANIFEST_CASES[case.case_id], case.canary).components
    assert {"emoji/pattern_match", "emoji/reported"} <= observed


# --- MCP tools --------------------------------------------------------------


def test_mcp_name_tools_carry_the_canary_in_the_name():
    tools = tools_for("mcp-name", CANARY)
    assert all(CANARY.lower() in t["function"]["name"] for t in tools)


def test_mcp_description_tools_carry_it_where_production_never_reads():
    """The recorded NOT_EVALUATED fact, exercised rather than asserted."""
    tools = tools_for("mcp-description", CANARY)
    assert all(t["function"]["description"] == CANARY for t in tools)
    assert all(CANARY not in t["function"]["name"] for t in tools)


def test_a_non_mcp_leaf_has_no_tools():
    assert tools_for("email", CANARY) is None
