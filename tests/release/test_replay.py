"""The replay record, and why a seed alone is not one."""

from __future__ import annotations

import dataclasses

import pytest

from tests.release.replay import (
    ReplayMismatch,
    ReplayState,
    canary_for,
    require_same_state,
)


def _state(**kw) -> ReplayState:
    base = dict(
        seed=1234,
        detector_config={"emoji": {"enabled": True}},
        component_schedule=("emoji/pattern_match", "emoji/reported"),
        branch_schedule=("allow", "report"),
        schema_revision="1b42ababed28",
        seeded_rows=(("policies", 2), ("interactions", 0)),
        browser_state={"localStorage": "{}", "sessionStorage": "{}"},
    )
    base.update(kw)
    return ReplayState(**base)


def test_the_record_carries_every_field_the_module_names():
    """A field named in the docstring and absent from the record is a field
    nobody reproduces."""
    fields = {f.name for f in dataclasses.fields(ReplayState)}
    assert fields == {
        "seed",
        "detector_config",
        "component_schedule",
        "branch_schedule",
        "schema_revision",
        "seeded_rows",
        "browser_state",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("detector_config", {"emoji": {"enabled": False}}),
        ("component_schedule", ("emoji/pattern_match",)),
        ("branch_schedule", ("allow",)),
        ("schema_revision", "f1ab8c9e9974"),
        ("seeded_rows", (("policies", 3),)),
        ("browser_state", {"localStorage": '{"k":"v"}', "sessionStorage": "{}"}),
    ],
)
def test_each_non_seed_field_changes_the_identifier(field: str, value):
    """The point of the whole module.

    If any of these left the identifier unchanged, two runs against different
    state would share an id and a diagnostic would send someone to the wrong
    reproduction.
    """
    assert _state().identifier != _state(**{field: value}).identifier


def test_the_seed_changes_the_identifier_too():
    assert _state().identifier != _state(seed=9999).identifier


def test_the_identifier_is_stable_for_identical_state():
    assert _state().identifier == _state().identifier


def test_key_order_does_not_change_the_identifier():
    """Otherwise the id is a property of dict construction, not of the state."""
    a = _state(detector_config={"emoji": {"enabled": True}, "topic": {"enabled": False}})
    b = _state(detector_config={"topic": {"enabled": False}, "emoji": {"enabled": True}})
    assert a.identifier == b.identifier


def test_canaries_are_derived_from_the_whole_state_not_the_seed():
    """A run whose detector configuration differs must not reuse another
    run's canaries and report a matching signature."""
    same_seed_other_config = _state(detector_config={"topic": {"enabled": True}})
    assert canary_for(_state(), "case-1") != canary_for(same_seed_other_config, "case-1")


def test_canaries_are_stable_and_case_specific():
    assert canary_for(_state(), "case-1") == canary_for(_state(), "case-1")
    assert canary_for(_state(), "case-1") != canary_for(_state(), "case-2")


def test_the_diagnostic_carries_the_identifier_and_the_seed():
    """A run artifact nobody reads is not a reproduction aid."""
    line = _state().diagnostic()
    assert _state().identifier in line
    assert "seed=1234" in line


def test_comparing_against_a_different_state_is_refused_and_names_the_fields():
    with pytest.raises(ReplayMismatch, match="differing: \\['schema_revision'\\]"):
        require_same_state(_state(), _state(schema_revision="other"))


def test_comparing_against_the_same_state_passes():
    require_same_state(_state(), _state())
