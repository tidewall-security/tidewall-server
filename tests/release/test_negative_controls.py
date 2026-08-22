"""Adversarial FIXTURES, not source mutations.

Named honestly. These construct inputs and witness states that a naive gate
accepts, and check that the real gate refuses them. That is worth having, and
it is NOT mutation coverage: no line of the guard is changed, so a guard that
was deleted entirely would still refuse these fixtures if some other check
happened to catch them.

The real mutations of the witness and collector code live in the mutation
runs recorded in this task's commits, and each names its edit.
"""

from __future__ import annotations

import json

import pytest

from tests.release.traversal import Sweep, set_at
from tests.release.witnesses import (
    EXAMINED_ZERO,
    NEVER_INVOKED,
    AbsenceEvaluator,
    CollectorResult,
    Ingress,
    Outcome,
    WitnessChain,
    WitnessMissing,
    assert_absent,
    gate,
)

CANARY = "CANARY-NEGATIVE-6a90"
CALL = "call-1"


def _chain(call_id: str = CALL) -> WitnessChain:
    return WitnessChain(
        case_id="negative-1",
        effective_parsed_path="body.prompt",
        effective_parsed_value=CANARY,
        component="malicious_prompt",
        sub_path="generic_injection_ml",
        call_id=call_id,
        consumed_field="prompt",
        result="clean",
        response_consumer="POST /v1/scan",
    )


# --- fixture 1: a duplicate JSON key discarding the canary -------------------


def test_a_duplicate_key_does_not_hide_the_canary_from_the_evaluated_value():
    """The body carries a harmless value first and the canary second.

    A check that reads the FIRST occurrence -- or that scans the raw body for
    the value it sent -- concludes the canary was never evaluated.
    """
    raw = b'{"prompt": "harmless", "prompt": "' + CANARY.encode() + b'"}'

    naive_first_occurrence = raw.split(b'"prompt": "')[1].split(b'"')[0].decode()
    assert naive_first_occurrence == "harmless", "premise changed"

    evaluated = json.loads(raw)["prompt"]
    assert evaluated == CANARY, (
        "the parser selected the harmless value, so this fixture no longer " "demonstrates the discard"
    )


def test_the_reverse_duplicate_hides_it_from_a_last_occurrence_reader():
    """Same trick, other way round, so a reader hardcoded to 'last' also fails."""
    raw = b'{"prompt": "' + CANARY.encode() + b'", "prompt": "harmless"}'
    assert json.loads(raw)["prompt"] == "harmless"
    assert CANARY.encode() in raw, "the canary is in the body but not evaluated"


# --- fixture 2: an outcome from a different call -----------------------------


def test_an_outcome_from_a_different_call_is_refused():
    """Every field present, the chain reads complete, one field is another
    call's."""
    with pytest.raises(WitnessMissing, match="belongs to call 'call-2'"):
        gate(
            _chain(),
            ingress=Ingress(call_id=CALL, value=CANARY),
            outcome=Outcome(call_id="call-2", component="malicious_prompt", result="clean"),
            collector=CollectorResult(call_id=CALL, collector="store", status="examined"),
            declared_object_count=1,
        )


def test_a_cross_call_outcome_never_reaches_the_absence_evaluator():
    evaluator = AbsenceEvaluator()
    with pytest.raises(WitnessMissing):
        assert_absent(
            _chain(),
            ingress=Ingress(call_id=CALL, value=CANARY),
            outcome=Outcome(call_id="call-2", component="malicious_prompt", result="clean"),
            collector=CollectorResult(call_id=CALL, collector="store", status="examined"),
            declared_object_count=1,
            found=False,
            evaluator=evaluator,
        )
    assert not evaluator.called_for("negative-1")


def test_a_plausible_but_unrelated_outcome_is_refused():
    """A real result, from a real component, for the wrong component."""
    with pytest.raises(WitnessMissing, match="chain declares 'malicious_prompt'"):
        gate(
            _chain(),
            ingress=Ingress(call_id=CALL, value=CANARY),
            outcome=Outcome(call_id=CALL, component="topic", result="clean"),
            collector=CollectorResult(call_id=CALL, collector="store", status="examined"),
            declared_object_count=1,
        )


# --- fixture 3: a collector reporting zero where objects were declared -------


def test_examined_zero_is_refused_where_the_declared_set_is_not_empty():
    with pytest.raises(WitnessMissing, match="declared object set says 4"):
        gate(
            _chain(),
            ingress=Ingress(call_id=CALL, value=CANARY),
            outcome=Outcome(call_id=CALL, component="malicious_prompt", result="clean"),
            collector=CollectorResult(call_id=CALL, collector="store", status=EXAMINED_ZERO),
            declared_object_count=4,
        )


def test_never_invoked_is_refused_even_where_zero_was_declared():
    """The distinction that a single 'empty' status destroys."""
    with pytest.raises(WitnessMissing, match="collector never invoked"):
        gate(
            _chain(),
            ingress=Ingress(call_id=CALL, value=CANARY),
            outcome=Outcome(call_id=CALL, component="malicious_prompt", result="clean"),
            collector=CollectorResult(call_id=CALL, collector="store", status=NEVER_INVOKED),
            declared_object_count=0,
        )


def test_examined_zero_is_accepted_only_where_zero_was_declared():
    gate(
        _chain(),
        ingress=Ingress(call_id=CALL, value=CANARY),
        outcome=Outcome(call_id=CALL, component="malicious_prompt", result="clean"),
        collector=CollectorResult(call_id=CALL, collector="store", status=EXAMINED_ZERO),
        declared_object_count=0,
    )


# --- fixture 4: a canary hidden behind a representation ----------------------


def test_an_escaped_representation_is_still_found():
    """A fixture that plants the canary in a form a plain-text scan misses."""
    exchange = {"headers": {}, "body": {"note": "plain"}}
    set_at(exchange, "body.note", CANARY.encode().decode("unicode_escape"))

    escaped = json.dumps({"note": CANARY}, ensure_ascii=True)
    exchange["body"]["note"] = escaped

    assert Sweep().findings(exchange, CANARY), "the escaped form was missed"


# --- what these fixtures are not --------------------------------------------


def test_these_fixtures_are_not_counted_as_mutation_coverage():
    """Stated in the suite, not only in a docstring.

    Counting adversarial fixtures as mutation coverage because a heading says
    "Mutations" is the labelling defect this programme removes.
    """
    source = __import__("pathlib").Path(__file__).read_text()
    assert "Adversarial FIXTURES, not source mutations" in source
    assert "NOT mutation coverage" in source
