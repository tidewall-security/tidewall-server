"""The gate, the two boundary classes, and the negative controls."""

from __future__ import annotations

import pytest

from tests.release.witnesses import (
    EXAMINED,
    EXAMINED_ZERO,
    NEVER_INVOKED,
    UNPARSED_BOUNDARY_KINDS,
    AbsenceEvaluator,
    BoundaryWitness,
    CollectorResult,
    Ingress,
    Outcome,
    ValidationWitness,
    WitnessChain,
    WitnessMissing,
    assert_absent,
    gate,
)

CALL = "call-8f21"


def _chain(case_id: str = "case-1", call_id: str = CALL) -> WitnessChain:
    return WitnessChain(
        case_id=case_id,
        effective_parsed_path="body.prompt",
        effective_parsed_value="CANARY",
        component="malicious_prompt",
        sub_path="generic_injection_ml",
        call_id=call_id,
        consumed_field="prompt",
        result="clean",
        response_consumer="POST /v1/scan",
    )


def _witnesses(call_id: str = CALL, status: str = EXAMINED):
    return dict(
        ingress=Ingress(call_id=call_id, value="CANARY"),
        outcome=Outcome(call_id=call_id, component="malicious_prompt", result="clean"),
        collector=CollectorResult(call_id=call_id, collector="store", status=status, objects=("row-1",)),
    )


# --- the gate ---------------------------------------------------------------


def test_a_complete_chain_passes_the_gate():
    gate(_chain(), **_witnesses(), declared_object_count=1)


@pytest.mark.parametrize("missing", ["ingress", "outcome", "collector"])
def test_each_missing_witness_refuses_the_gate(missing: str):
    w = _witnesses()
    w[missing] = None
    with pytest.raises(WitnessMissing, match=f"no {missing} witness"):
        gate(_chain(), **w, declared_object_count=1)


@pytest.mark.parametrize("wrong", ["ingress", "outcome", "collector"])
def test_a_witness_from_a_different_call_refuses_the_gate(wrong: str):
    """The cross-call negative control.

    Every field is present and the chain reads complete; one of them belongs
    to another call. Matching by anything but call id accepts this.
    """
    w = _witnesses()
    if wrong == "ingress":
        w["ingress"] = Ingress(call_id="call-other", value="CANARY")
    elif wrong == "outcome":
        w["outcome"] = Outcome(call_id="call-other", component="malicious_prompt", result="clean")
    else:
        w["collector"] = CollectorResult(call_id="call-other", collector="store", status=EXAMINED)

    with pytest.raises(WitnessMissing, match="belongs to call 'call-other'"):
        gate(_chain(), **w, declared_object_count=1)


def test_an_outcome_from_a_different_component_refuses_the_gate():
    """A result exists, for the wrong thing."""
    w = _witnesses()
    w["outcome"] = Outcome(call_id=CALL, component="topic", result="clean")
    with pytest.raises(WitnessMissing, match="chain declares 'malicious_prompt'"):
        gate(_chain(), **w, declared_object_count=1)


def test_a_collector_that_never_ran_refuses_the_gate():
    with pytest.raises(WitnessMissing, match="collector never invoked"):
        gate(_chain(), **_witnesses(status=NEVER_INVOKED), declared_object_count=0)


def test_examined_zero_passes_only_where_the_declared_set_says_zero():
    gate(_chain(), **_witnesses(status=EXAMINED_ZERO), declared_object_count=0)


def test_examined_zero_refuses_the_gate_when_objects_were_declared():
    """An empty result is only acceptable where emptiness was expected."""
    with pytest.raises(WitnessMissing, match="declared object set says 3"):
        gate(_chain(), **_witnesses(status=EXAMINED_ZERO), declared_object_count=3)


def test_never_invoked_and_examined_zero_are_distinguishable():
    """Only the first can pass. Collapsing them loses the whole distinction."""
    assert NEVER_INVOKED != EXAMINED_ZERO
    with pytest.raises(WitnessMissing, match="never invoked"):
        gate(_chain(), **_witnesses(status=NEVER_INVOKED), declared_object_count=0)
    gate(_chain(), **_witnesses(status=EXAMINED_ZERO), declared_object_count=0)


def test_an_unknown_collector_status_is_refused_at_construction():
    with pytest.raises(ValueError, match="unknown collector status"):
        CollectorResult(call_id=CALL, collector="store", status="probably-fine")


# --- absence is evaluated only behind the gate ------------------------------


def test_absence_is_evaluated_when_the_gate_holds():
    e = AbsenceEvaluator()
    assert_absent(_chain(), **_witnesses(), declared_object_count=1, found=False, evaluator=e)
    assert e.called_for("case-1")


def test_a_present_canary_fails_when_absence_was_asserted():
    e = AbsenceEvaluator()
    with pytest.raises(AssertionError, match="canary present"):
        assert_absent(_chain(), **_witnesses(), declared_object_count=1, found=True, evaluator=e)


def test_absence_is_never_evaluated_when_a_witness_is_missing():
    """The assertion that can kill a gate mutation.

    A case with an absent witness already fails, so "the case fails" is
    identical before and after mutating the gate. What differs is whether the
    evaluator was CALLED.
    """
    e = AbsenceEvaluator()
    w = _witnesses()
    w["outcome"] = None
    with pytest.raises(WitnessMissing):
        assert_absent(_chain(), **w, declared_object_count=1, found=False, evaluator=e)
    assert not e.called_for("case-1"), "the absence evaluator ran for a case whose witness was missing"


def test_absence_is_never_evaluated_for_a_cross_call_witness():
    e = AbsenceEvaluator()
    w = _witnesses()
    w["outcome"] = Outcome(call_id="call-other", component="malicious_prompt", result="clean")
    with pytest.raises(WitnessMissing):
        assert_absent(_chain(), **w, declared_object_count=1, found=False, evaluator=e)
    assert not e.called_for("case-1")


def test_absence_is_never_evaluated_when_the_collector_never_ran():
    e = AbsenceEvaluator()
    with pytest.raises(WitnessMissing):
        assert_absent(
            _chain(),
            **_witnesses(status=NEVER_INVOKED),
            declared_object_count=0,
            found=False,
            evaluator=e,
        )
    assert not e.called_for("case-1")


# --- the unparsed boundary class --------------------------------------------


@pytest.mark.parametrize("kind", sorted(UNPARSED_BOUNDARY_KINDS))
def test_each_unparsed_boundary_kind_needs_no_component_or_call_id(kind: str):
    """These paths end before any component runs.

    Requiring a call id here forces a fabricated one, a skipped gate, or a
    dropped case.
    """
    w = BoundaryWitness(
        case_id=f"case-{kind}",
        kind=kind,
        raw_asgi_request=b"POST /v1/scan HTTP/1.1\r\n\r\n{bad",
        status=400,
        exchange_id="exchange-1",
    )
    assert w.kind == kind
    assert not hasattr(w, "call_id")


def test_role_and_grant_denial_are_unparsed_boundaries():
    """Both were dropped once when this step was rewritten into two classes."""
    assert "role-denial" in UNPARSED_BOUNDARY_KINDS
    assert "grant-denial" in UNPARSED_BOUNDARY_KINDS


def test_an_unknown_boundary_kind_is_refused():
    with pytest.raises(ValueError, match="not an unparsed boundary kind"):
        BoundaryWitness(case_id="c", kind="probably-unparsed", raw_asgi_request=b"", status=400, exchange_id="e")


# --- model validation is a third class --------------------------------------


def test_model_validation_carries_the_parser_selected_value():
    """A duplicate JSON key makes raw body and effective value differ.

    That difference is the entire reason the 422 case exists, so asserting on
    the raw body checks a string the application never evaluated.
    """
    raw = b'{"prompt": "harmless", "prompt": "CANARY"}'
    w = ValidationWitness(
        case_id="case-422",
        parsed_value="CANARY",
        validation_location="body.prompt",
        status=422,
        exchange_id="exchange-2",
    )
    import json

    assert (
        json.loads(raw)["prompt"] == w.parsed_value
    ), "premise changed: the parser no longer selects the last duplicate key"
    assert w.parsed_value != "harmless"


def test_model_validation_is_not_an_unparsed_boundary():
    assert "model-validation" not in UNPARSED_BOUNDARY_KINDS
    assert not isinstance(
        ValidationWitness(case_id="c", parsed_value="v", validation_location="body.x", status=422, exchange_id="e"),
        BoundaryWitness,
    )
