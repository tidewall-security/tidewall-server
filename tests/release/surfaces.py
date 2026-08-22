"""The EVALUATED INPUT at each boundary -- the value the code actually saw.

Asserting on the value a test SENT is asserting on a string the application
may never have evaluated. Between the two sit a parser, a serialiser, a
normaliser and a truncation, and each of them can change the value in ways
that matter:

  * a duplicate JSON key means the raw body carries two values and the parser
    selects one -- which is the entire reason the 422 case exists;
  * a detector receives concatenated message content, not the request body;
  * `evaluate_access_rules` receives a rule set, not text at all.

So each boundary has its OWN notion of evaluated input, and a witness records
what that boundary received rather than what a caller hoped it would.

RAW BODY IS THE EVALUATED INPUT ONLY WHERE NOTHING PARSED IT -- malformed
JSON, auth before body, an unknown route. Using it elsewhere is the same
error in the other direction.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from tests.release.witnesses import Ingress


class NotEvaluated(Exception):
    """No component received anything at this boundary."""


@dataclass
class EvaluatedInputs:
    """Every value a component was observed to receive, in call order."""

    received: list[tuple[str, str]] = field(default_factory=list)

    def record(self, component: str, value: str) -> None:
        self.received.append((component, value))

    def for_component(self, component: str) -> list[str]:
        return [v for c, v in self.received if c == component]

    def ingress(self, component: str, call_id: str) -> Ingress:
        values = self.for_component(component)
        if not values:
            raise NotEvaluated(
                f"{component} received nothing; an absence assertion behind this "
                "witness would be measuring a component that never ran"
            )
        return Ingress(call_id=call_id, value=values[0])


@contextmanager
def recording_detector_inputs(engine: Any) -> Any:
    """Record the text each detector actually receives from the engine.

    Wraps the bound detectors rather than patching the class, so the engine's
    own dispatch -- including which detectors it decides to skip -- is
    unchanged. A recorder that drives the detectors itself would measure the
    recorder.
    """
    inputs = EvaluatedInputs()
    originals = []

    for index, (name, detector) in enumerate(engine._detectors):
        original = detector.scan

        def wrapped(text: str, _original=original, _name=name, **kwargs: Any):
            inputs.record(_name, text)
            return _original(text, **kwargs)

        detector.scan = wrapped
        originals.append((index, detector, original))

    try:
        yield inputs
    finally:
        for _index, detector, original in originals:
            detector.scan = original


def parser_selected(raw_body: bytes, path: str) -> str:
    """What the JSON parser selects, which is not always what was sent.

    With a duplicate key the raw body carries both values and the parser keeps
    the last. A test asserting on the first is asserting on a value the
    application discarded.
    """
    data = json.loads(raw_body)
    cursor: Any = data
    for part in path.split("."):
        cursor = cursor[part]
    return cursor


def raw_body_is_the_evaluated_input(boundary_kind: str) -> bool:
    """True only where nothing parsed the request."""
    from tests.release.witnesses import UNPARSED_BOUNDARY_KINDS

    return boundary_kind in UNPARSED_BOUNDARY_KINDS
