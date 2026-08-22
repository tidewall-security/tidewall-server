"""The evaluated input at each boundary, against real components."""

from __future__ import annotations

import warnings

import pytest

from tests.release.surfaces import (
    EvaluatedInputs,
    NotEvaluated,
    parser_selected,
    raw_body_is_the_evaluated_input,
    recording_detector_inputs,
)

warnings.filterwarnings("ignore")

CANARY = "CANARY-EVALUATED-3c19"


def _engine(config: dict):
    from app.scanner_engine import ScannerEngine

    return ScannerEngine.from_detectors(config)


# --- the detector's received value ------------------------------------------


def test_the_detectors_received_value_is_recorded():
    engine = _engine({"emoji": {"enabled": True}})
    with recording_detector_inputs(engine) as inputs:
        engine.scan(f"{CANARY} \U0001f600", event_type="input", vault_id="v", vault=None)

    received = inputs.for_component("emoji")
    assert received, "no detector input was recorded at all"
    assert CANARY in received[0]


def test_the_recorder_does_not_change_which_detectors_run():
    """A recorder that drives the detectors itself measures the recorder.

    malicious_entity is output-only, so on an input event the engine skips it
    -- and the recording must show that skip rather than defeating it.
    """
    engine = _engine({"emoji": {"enabled": True}, "malicious_entity": {"enabled": True}})
    with recording_detector_inputs(engine) as inputs:
        engine.scan("hi \U0001f600", event_type="input", vault_id="v", vault=None)

    assert inputs.for_component("emoji"), "the applicable detector did not run"
    assert not inputs.for_component("malicious_entity"), "an inapplicable detector was driven by the recorder"


def test_the_wrapper_is_removed_afterwards():
    """Otherwise every later test measures a wrapped engine."""
    engine = _engine({"emoji": {"enabled": True}})
    before = {name: detector.scan for name, detector in engine._detectors}
    with recording_detector_inputs(engine):
        pass
    after = {name: detector.scan for name, detector in engine._detectors}
    assert before == after


def test_an_ingress_witness_comes_from_what_was_received():
    engine = _engine({"emoji": {"enabled": True}})
    with recording_detector_inputs(engine) as inputs:
        engine.scan(f"{CANARY} \U0001f600", event_type="input", vault_id="v", vault=None)

    ingress = inputs.ingress("emoji", call_id="call-1")
    assert ingress.call_id == "call-1"
    assert CANARY in ingress.value


def test_a_component_that_received_nothing_refuses_to_supply_a_witness():
    """The gate depends on this. A fabricated ingress makes every downstream
    absence assertion pass while measuring a component that never ran."""
    with pytest.raises(NotEvaluated, match="received nothing"):
        EvaluatedInputs().ingress("emoji", call_id="call-1")


def test_the_evaluated_value_is_not_the_request_body():
    """A detector receives assembled message content, not the body.

    Asserting on the body would check a string the detector never saw.
    """
    engine = _engine({"emoji": {"enabled": True}})
    body = f'{{"messages": [{{"content": "{CANARY} \\ud83d\\ude00"}}]}}'
    with recording_detector_inputs(engine) as inputs:
        engine.scan(f"{CANARY} \U0001f600", event_type="input", vault_id="v", vault=None)

    received = inputs.for_component("emoji")[0]
    assert received != body, "the detector received the raw request body verbatim"
    assert CANARY in received


# --- the parser-selected value ----------------------------------------------


def test_a_duplicate_key_makes_the_raw_body_and_the_evaluated_value_differ():
    """The entire reason the 422 case exists."""
    raw = b'{"prompt": "harmless", "prompt": "' + CANARY.encode() + b'"}'
    assert b"harmless" in raw

    selected = parser_selected(raw, "prompt")
    assert selected == CANARY, "premise changed: the parser no longer selects the last duplicate key"
    assert selected != "harmless"


def test_the_parser_selected_value_reaches_a_nested_path():
    raw = b'{"body": {"policy": {"name": "' + CANARY.encode() + b'"}}}'
    assert parser_selected(raw, "body.policy.name") == CANARY


# --- raw body is evaluated input only where nothing parsed ------------------


@pytest.mark.parametrize("kind", ["malformed-json", "auth-before-body", "role-denial", "grant-denial"])
def test_raw_body_is_the_evaluated_input_for_unparsed_boundaries(kind: str):
    assert raw_body_is_the_evaluated_input(kind)


def test_raw_body_is_not_the_evaluated_input_for_model_validation():
    """The same error in the other direction."""
    assert not raw_body_is_the_evaluated_input("model-validation")


def test_raw_body_is_not_the_evaluated_input_for_a_detector_path():
    assert not raw_body_is_the_evaluated_input("malicious_prompt")
