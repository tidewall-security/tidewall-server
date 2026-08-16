"""Access rule evaluation engine.

Evaluates access rules sequentially (top-down by sort_order) against
request metadata. Rules that match execute their then_action; rules
that don't match execute their else_action.

Actions:
- continue: proceed to next rule (or detectors if last rule)
- report_and_continue: log the match, proceed to next rule
- report_and_stop: log the match, stop rule evaluation (skip detectors)
- block_and_stop: block the request, stop evaluation
- ignore_and_stop: stop evaluation silently (no logging)
"""

from __future__ import annotations

from typing import Any

_STOP_ACTIONS = {"block_and_stop", "report_and_stop", "ignore_and_stop"}


def _evaluate_condition(condition: dict[str, Any], metadata: dict[str, Any]) -> bool:
    """Evaluate a single condition against metadata.

    Condition format: {"field": "model", "op": "==", "value": "deepseek"}
    """
    field = condition.get("field", "")
    op = condition.get("op", "==")
    expected = condition.get("value")

    actual = metadata.get(field)
    if actual is None:
        return False

    if op == "==":
        return bool(actual == expected)
    elif op == "!=":
        return bool(actual != expected)
    elif op == "contains":
        return isinstance(actual, str) and isinstance(expected, str) and expected in actual
    elif op == "not contains":
        return isinstance(actual, str) and isinstance(expected, str) and expected not in actual
    elif op == "in":
        return isinstance(expected, list) and actual in expected
    elif op == "not in":
        return isinstance(expected, list) and actual not in expected
    else:
        # Returning False here meant a block rule with a typo'd operator never
        # fired, silently removing the control. Validation rejects unknown
        # operators at write time; reaching this point is a bug or an
        # unvalidated write path, and must not be reported as "no match".
        raise ValueError(f"unknown access-rule operator: {op!r}")


def evaluate_access_rules(
    rules: list[dict[str, Any]],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate access rules sequentially against request metadata.

    Args:
        rules: List of rule dicts with name, conditions, then_action, else_action.
               Must be pre-sorted by sort_order.
        metadata: Request metadata (user_id, app_id, model, llm_provider, etc.)

    Returns:
        Dict with:
        - action: final action (continue, block_and_stop, etc.)
        - matched_rules: list of rules that matched with their actions
        - blocked: bool
    """
    matched_rules: list[dict[str, Any]] = []
    final_action = "continue"

    for rule in rules:
        conditions = rule.get("conditions", {})
        matched = _evaluate_condition(conditions, metadata)

        action = rule.get("then_action", "continue") if matched else rule.get("else_action", "continue")

        if matched or action in _STOP_ACTIONS:
            matched_rules.append(
                {
                    "name": rule.get("name", "unnamed"),
                    "matched": matched,
                    "action": action,
                }
            )

        if action in _STOP_ACTIONS:
            final_action = action
            break

    return {
        "action": final_action,
        "matched_rules": matched_rules,
        "blocked": final_action == "block_and_stop",
    }
