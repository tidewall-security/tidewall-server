"""Drive a manifest case through PRODUCTION and collect what it really produced.

The suites this replaces asserted that their case list matched the manifest,
then ran synthetic checks over hand-built `Emitted` objects. A review broke
`EmojiDetector.scan` to return `detected=False` unconditionally and both
suites still passed 170/170. They were named for a property they never
exercised.

So a case is now RUN. The engine is the real `ScannerEngine`, the detector is
the real detector, the observation is the real line trace, and the surfaces
collected are the real result fields and the real store. Every occurrence
found is routed through the real resolver.

WHAT THIS CANNOT DO IN A UNIT ENVIRONMENT is pretended nowhere: cases whose
detector needs a model that is not present cannot execute, and those are
reported as SKIPPED-WITH-A-REASON rather than counted as passes. A case that
did not run has not passed.
"""

from __future__ import annotations

import sqlite3
import warnings
from dataclasses import dataclass, field

from tests.release.observation import all_regions, observing
from tests.release.surfaces import recording_detector_inputs
from tests.release.witnesses import (
    EXAMINED,
    EXAMINED_ZERO,
    CollectorResult,
    Ingress,
    Outcome,
    WitnessChain,
)

warnings.filterwarnings("ignore")

#: Detectors that run without a downloaded model in this environment.
#: Measured, not assumed -- see test_execution.py, which asserts each one
#: actually reaches a marked component.
SELF_CONTAINED_DETECTORS: frozenset[str] = frozenset({"emoji", "confidential_and_pii_entity", "mcp_validation"})

#: The event each event-scoped detector requires (`_detector_applies`).
EVENT_FOR: dict[str, str] = {"malicious_entity": "output", "mcp_validation": "tool_listing"}


class CaseNotExecutable(Exception):
    """The case cannot run here, with the reason. NOT a pass."""


@dataclass
class Execution:
    """One case, actually run, with everything it produced."""

    case_id: str
    canary: str
    planted: str
    wire: str
    detector: str
    event: str
    result: object
    components: set[str] = field(default_factory=set)
    received: list[str] = field(default_factory=list)
    call_id: str = ""

    def surfaces(self) -> dict[str, str]:
        """Every field of the result a caller can see, as text."""
        from tests.release.states import SURFACE_FIELDS

        return {f: repr(getattr(self.result, f, None)) for f in SURFACE_FIELDS}

    def occurrences_of(self, value: str) -> dict[str, int]:
        """Where the canary actually appears in the produced surfaces."""
        return {field_name: text.count(value) for field_name, text in self.surfaces().items() if value in text}


def encode_for(representation: str, value: str) -> str:
    """The planted value in one representation family's form.

    Six of the seven families are byte-identical for ASCII text, which is why
    an ASCII probe collapses them; the encoders are still applied so a case
    declaring a family genuinely carries that family's bytes when they differ.
    """
    from tests.release.representations import FAMILIES

    family = next((f for f in FAMILIES if f.name == representation), None)
    if family is None:
        raise CaseNotExecutable(f"unknown representation {representation!r}")
    return family.encode(value).decode("utf-8", "surrogateescape")


def decode_at_boundary(representation: str, wire: str) -> str:
    """What the boundary hands on after decoding this family's wire form.

    This is the step whose absence made every representation case identical.
    Instrumented by `decoded_differs_from_wire` so a suite can assert the
    decode actually did something for the families where it should.
    """
    from tests.release.representations import decode

    return decode(representation, wire)


def decoded_differs_from_wire(representation: str, value: str) -> bool:
    """Whether this family's wire form is distinguishable for `value`.

    Six of seven families are byte-identical for ASCII, so a test asserting
    "the decode changed something" must only demand it where it is true.
    """
    return encode_for(representation, value) != value


def execute(case, canary: str) -> Execution:
    """Run one manifest case against the real engine."""
    from app.scanner_engine import ScannerEngine

    if case.detector not in SELF_CONTAINED_DETECTORS:
        raise CaseNotExecutable(
            f"{case.detector} needs a model that is not present in this "
            "environment; the case did not run and has not passed"
        )

    from tests.release.leaves import shape, tools_for

    event = EVENT_FOR.get(case.detector, case.event)
    engine = ScannerEngine.from_detectors({case.detector: {"enabled": True}})

    # The planted value is SHAPED BY THE LEAF. A detector looking for a credit
    # card correctly ignores an opaque token, and feeding every case the same
    # shapeless canary made 27 of them observe a "found nothing" state while
    # declaring a "found something" one.
    plain = shape(case.leaf, canary, case.sub_path)

    # THE REPRESENTATION IS APPLIED AT THE WIRE AND DECODED AT THE BOUNDARY,
    # which is what a real ingress does. Handing the ESCAPED form straight to a
    # detector skips the decode entirely, and a detector matching emoji
    # codepoints correctly fails to match the ASCII text `\ud83d\ude00`.
    #
    # Before this, the representation was used only to LABEL the emitted
    # signature: every case ran identical plain text, the manifest's seven-fold
    # multiplicity was accepted without being driven, and a broken decoder
    # could not fail any suite. A label is not a drive.
    wire = encode_for(case.representation, plain)
    text = decode_at_boundary(case.representation, wire)
    tools = tools_for(case.leaf, canary)

    from contextlib import nullcontext

    from tests.release.faults import INJECTED_STATES, injected

    # A case declaring a FAILURE STATE cannot reach it by input shaping. The
    # driver must produce the state, or the case observes a success state
    # while declaring a failure one -- and reports a pass.
    fault = nullcontext()
    if case.sub_path in INJECTED_STATES:
        detector = dict(engine._detectors)[case.detector]
        fault = injected(detector, case.sub_path)

    with fault, recording_detector_inputs(engine) as inputs, observing() as observation:
        result = engine.scan(text, event_type=event, vault_id="v", vault=None, tools=tools)

    return Execution(
        case_id=case.identity,
        canary=canary,
        planted=text,
        wire=wire,
        detector=case.detector,
        event=event,
        result=result,
        components=observation.components(all_regions()),
        received=inputs.for_component(case.detector),
        call_id=f"call-{case.identity}",
    )


def is_not_evaluated(case) -> str | None:
    """The recorded reason this component never evaluates this leaf, if any.

    A case whose component does not read its leaf must NOT pass the ordinary
    declared-component and evaluated-input checks: the component is reached,
    but for reasons having nothing to do with the planted value.
    """
    from tests.release.manifest import NOT_EVALUATED

    return NOT_EVALUATED.get((case.leaf, case.component, case.sub_path))


def evaluated_path_and_value(execution: Execution, case) -> tuple[str, str]:
    """Where the component actually read from, and what it read."""
    if case.leaf == "mcp-name":
        return "tools[*].function.name", execution.planted
    if case.leaf in ("mcp-description", "mcp-parameters"):
        # Placed, and never read. Naming the placement rather than a field the
        # component consumed is the honest record.
        return f"tools[*].function.{case.leaf.removeprefix('mcp-')}", execution.planted
    return "scan.text", execution.received[0] if execution.received else ""


def chain_for(execution: Execution, case) -> WitnessChain:
    """A witness chain built from what was OBSERVED, not declared."""
    # The witness names the field the component ACTUALLY reads. Reporting
    # `scan.text` for a tool-placement case claimed the detector consumed the
    # scan text, when MCPValidationDetector reads `function.name` and never
    # looks at the text at all.
    path, value = evaluated_path_and_value(execution, case)
    return WitnessChain(
        case_id=execution.case_id,
        effective_parsed_path=path,
        effective_parsed_value=value,
        component=case.component,
        sub_path=case.sub_path,
        call_id=execution.call_id,
        consumed_field=path.rsplit(".", 1)[-1],
        result=repr(getattr(execution.result, "blocked", None)),
        response_consumer=f"ScannerEngine.scan/{execution.event}",
    )


def witnesses_for(execution: Execution, store_rows: int):
    """Ingress, outcome and collector witnesses, all on this call's id."""
    if not execution.received:
        raise CaseNotExecutable(
            f"{execution.case_id}: the detector received nothing, so an absence "
            "assertion behind this witness would measure a component that never ran"
        )
    return (
        Ingress(call_id=execution.call_id, value=execution.received[0]),
        Outcome(
            call_id=execution.call_id,
            component=execution.detector,
            result=repr(getattr(execution.result, "blocked", None)),
        ),
        CollectorResult(
            call_id=execution.call_id,
            collector="scan-result",
            status=EXAMINED if store_rows else EXAMINED_ZERO,
            objects=tuple(execution.surfaces()),
        ),
    )


def store_occurrences(db, needle: bytes) -> int:
    """Read the real store's bytes, not a reported number."""
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    finally:
        conn.close()
    from pathlib import Path

    return Path(db).read_bytes().count(needle)
