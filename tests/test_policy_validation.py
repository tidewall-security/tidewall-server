"""Write-time policy validation.

Three security predicates used to fail *open* on invalid configuration, none of
them inside DetectorResult, so none was covered by the detector-status work. A
typo in an administrator's policy silently removed a control.
"""

from __future__ import annotations

import pytest

from app.services.policy_validation import (
    PolicyValidationError,
    validate_access_rules,
    validate_cidr,
    validate_detectors,
    validate_operator,
    validate_prompt_list_entry,
    validate_regex,
)


def test_valid_regex_accepted():
    validate_regex(r"PROJ-\d+", where="test")


def test_invalid_regex_rejected():
    with pytest.raises(PolicyValidationError, match="invalid regex"):
        validate_regex("(unclosed", where="test")


def test_overlong_pattern_rejected():
    with pytest.raises(PolicyValidationError, match="over the"):
        validate_regex("a" * 1001, where="test")


def test_unknown_operator_rejected():
    """An unknown operator returned False, so a block rule never fired."""
    with pytest.raises(PolicyValidationError, match="unknown operator"):
        validate_operator("kinda equals", where="test")
    # "equals" reads like a valid operator but the evaluator spells it "==".
    with pytest.raises(PolicyValidationError, match="unknown operator"):
        validate_operator("equals", where="test")


@pytest.mark.parametrize("op", ["==", "!=", "contains", "not contains", "in", "not in"])
def test_evaluator_operators_are_accepted(op):
    validate_operator(op, where="test")


def test_operator_set_matches_the_evaluator():
    """If these drift, an operator valid at write time fails open at evaluation."""
    import inspect

    from app.services import rule_evaluator
    from app.services.policy_validation import VALID_OPERATORS

    source = inspect.getsource(rule_evaluator)
    for op in VALID_OPERATORS:
        assert f'op == "{op}"' in source, f"{op!r} is accepted at write time but absent from the evaluator"


def test_invalid_cidr_rejected():
    with pytest.raises(PolicyValidationError, match="invalid CIDR"):
        validate_cidr("10.0.0.0/33", where="test")


def test_valid_cidr_accepted():
    validate_cidr("10.0.0.0/8", where="test")


def test_unknown_detector_rejected():
    with pytest.raises(PolicyValidationError, match="no such detector"):
        validate_detectors({"no_such_detector": {"enabled": True}})


def test_disabled_unknown_detector_is_allowed():
    """A disabled entry cannot remove a control, so it need not be rejected."""
    validate_detectors({"no_such_detector": {"enabled": False}})


def test_unknown_action_rejected():
    with pytest.raises(PolicyValidationError, match="unknown action"):
        validate_detectors({"topic": {"enabled": True, "action": "destroy"}})


def test_invalid_detector_pattern_rejected():
    with pytest.raises(PolicyValidationError, match="invalid regex"):
        validate_detectors({"custom_entity": {"enabled": True, "patterns": ["(unclosed"]}})


def test_valid_detectors_accepted():
    validate_detectors(
        {
            "topic": {"enabled": True, "action": "report"},
            "custom_entity": {"enabled": True, "action": "redact", "patterns": [r"PROJ-\d+"]},
        }
    )


def test_access_rule_with_unknown_operator_rejected():
    with pytest.raises(PolicyValidationError, match="unknown operator"):
        validate_access_rules([{"conditions": [{"field": "user_id", "op": "sorta", "value": "x"}]}])


def test_access_rule_without_op_defaults_to_equality():
    """The evaluator defaults `op` to "==", so an absent key is valid."""
    validate_access_rules([{"conditions": [{"field": "user_id", "value": "x"}]}])


def test_prompt_list_regex_validated():
    with pytest.raises(PolicyValidationError, match="invalid regex"):
        validate_prompt_list_entry("(unclosed", "regex")
    validate_prompt_list_entry("(unclosed", "substring")  # not a regex, so not compiled


def test_prompt_list_unknown_match_type_rejected():
    with pytest.raises(PolicyValidationError, match="unknown match_type"):
        validate_prompt_list_entry("x", "fuzzy")


def test_unknown_operator_raises_at_evaluation_rather_than_matching_nothing():
    """Defence in depth for anything that bypassed write-time validation."""
    from app.services.rule_evaluator import _evaluate_condition

    with pytest.raises(ValueError, match="unknown access-rule operator"):
        _evaluate_condition({"field": "model", "op": "sorta equals", "value": "x"}, {"model": "x"})
