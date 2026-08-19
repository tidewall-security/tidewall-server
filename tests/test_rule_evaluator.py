"""Tests for access rule evaluation logic."""


def test_no_rules_returns_continue():
    from app.services.rule_evaluator import evaluate_access_rules

    result = evaluate_access_rules(rules=[], metadata={})
    assert result["action"] == "continue"
    assert result["matched_rules"] == []


def test_simple_equals_match_blocks():
    from app.services.rule_evaluator import evaluate_access_rules

    rules = [
        {
            "name": "block deepseek",
            "conditions": {"field": "model", "op": "==", "value": "deepseek"},
            "then_action": "block_and_stop",
            "else_action": "continue",
        }
    ]
    result = evaluate_access_rules(rules, metadata={"model": "deepseek"})
    assert result["action"] == "block_and_stop"
    assert len(result["matched_rules"]) == 1
    assert result["matched_rules"][0]["name"] == "block deepseek"


def test_equals_no_match_continues():
    from app.services.rule_evaluator import evaluate_access_rules

    rules = [
        {
            "name": "block deepseek",
            "conditions": {"field": "model", "op": "==", "value": "deepseek"},
            "then_action": "block_and_stop",
            "else_action": "continue",
        }
    ]
    result = evaluate_access_rules(rules, metadata={"model": "gpt-4o"})
    assert result["action"] == "continue"


def test_not_equals_operator():
    from app.services.rule_evaluator import evaluate_access_rules

    rules = [
        {
            "name": "allow only gpt",
            "conditions": {"field": "model", "op": "!=", "value": "gpt-4o"},
            "then_action": "block_and_stop",
            "else_action": "continue",
        }
    ]
    result = evaluate_access_rules(rules, metadata={"model": "deepseek"})
    assert result["action"] == "block_and_stop"


def test_contains_operator():
    from app.services.rule_evaluator import evaluate_access_rules

    rules = [
        {
            "name": "block external users",
            "conditions": {"field": "user_id", "op": "contains", "value": "@external.com"},
            "then_action": "block_and_stop",
            "else_action": "continue",
        }
    ]
    result = evaluate_access_rules(rules, metadata={"user_id": "mallory@external.com"})
    assert result["action"] == "block_and_stop"


def test_in_operator():
    from app.services.rule_evaluator import evaluate_access_rules

    rules = [
        {
            "name": "block banned models",
            "conditions": {"field": "model", "op": "in", "value": ["deepseek", "llama-uncensored"]},
            "then_action": "block_and_stop",
            "else_action": "continue",
        }
    ]
    result = evaluate_access_rules(rules, metadata={"model": "deepseek"})
    assert result["action"] == "block_and_stop"


def test_sequential_evaluation_stops_on_block():
    from app.services.rule_evaluator import evaluate_access_rules

    rules = [
        {
            "name": "first rule blocks",
            "conditions": {"field": "model", "op": "==", "value": "deepseek"},
            "then_action": "block_and_stop",
            "else_action": "continue",
        },
        {
            "name": "second rule reports",
            "conditions": {"field": "user_id", "op": "==", "value": "admin"},
            "then_action": "report_and_continue",
            "else_action": "continue",
        },
    ]
    result = evaluate_access_rules(rules, metadata={"model": "deepseek", "user_id": "admin"})
    assert result["action"] == "block_and_stop"
    assert len(result["matched_rules"]) == 1


def test_report_and_continue_collects_multiple():
    from app.services.rule_evaluator import evaluate_access_rules

    rules = [
        {
            "name": "report external",
            "conditions": {"field": "user_id", "op": "contains", "value": "@external"},
            "then_action": "report_and_continue",
            "else_action": "continue",
        },
        {
            "name": "report deepseek",
            "conditions": {"field": "model", "op": "==", "value": "deepseek"},
            "then_action": "report_and_continue",
            "else_action": "continue",
        },
    ]
    result = evaluate_access_rules(rules, metadata={"user_id": "user@external.com", "model": "deepseek"})
    assert result["action"] == "continue"  # report_and_continue doesn't stop
    assert len(result["matched_rules"]) == 2


def test_missing_metadata_field_treated_as_no_match():
    from app.services.rule_evaluator import evaluate_access_rules

    rules = [
        {
            "name": "check model",
            "conditions": {"field": "model", "op": "==", "value": "deepseek"},
            "then_action": "block_and_stop",
            "else_action": "continue",
        }
    ]
    result = evaluate_access_rules(rules, metadata={})
    assert result["action"] == "continue"
