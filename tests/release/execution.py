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
    text = shape(case.leaf, canary, case.sub_path)
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
        detector=case.detector,
        event=event,
        result=result,
        components=observation.components(all_regions()),
        received=inputs.for_component(case.detector),
        call_id=f"call-{case.identity}",
    )


def chain_for(execution: Execution, case) -> WitnessChain:
    """A witness chain built from what was OBSERVED, not declared."""
    return WitnessChain(
        case_id=execution.case_id,
        effective_parsed_path="scan.text",
        effective_parsed_value=execution.received[0] if execution.received else "",
        component=case.component,
        sub_path=case.sub_path,
        call_id=execution.call_id,
        consumed_field="text",
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
