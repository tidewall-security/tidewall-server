"""Shared machinery for the two canary suites.

The suites differ in one axis -- capture off versus on -- and in nothing else.
Sharing the machinery is what keeps the difference to that axis: two suites
written separately drift, and the drift looks like a finding.

Every failure carries the replay identifier, so a diagnostic is reproducible
without hunting for the run artifact.
"""

from __future__ import annotations

from dataclasses import dataclass

from tests.release.consumer import (
    Emitted,
    check_emitted_are_resolved,
    check_required_are_emitted,
)
from tests.release.manifest import load_cases
from tests.release.replay import ReplayState, canary_for

#: Concrete values, recorded rather than sampled. Task 6 step 1 requires the
#: replay state to be reconstructible from the record alone.
SUITE_STATE = ReplayState(
    seed=20260822,
    detector_config={
        "emoji": {"enabled": True},
        "confidential_and_pii_entity": {"enabled": True},
        "mcp_validation": {"enabled": True},
    },
    component_schedule=(
        "emoji/pattern_match",
        "emoji/reported",
        "pii/entities_redacted",
        "pii/no_entities",
        "mcp_validation/name_similarity",
    ),
    branch_schedule=("allow", "report", "alert", "transform", "degraded", "tool-listing"),
    schema_revision="1b42ababed28",
    seeded_rows=(("policies", 2), ("interactions", 0)),
    browser_state={"localStorage": "{}", "sessionStorage": "{}"},
)


@dataclass(frozen=True)
class SuiteCase:
    """A manifest case, with its deterministic canary bound to it."""

    case_id: str
    canary: str
    leaf: str
    placement: str
    branch: str
    detector: str
    event: str
    capture: str
    operation: str
    grant: str
    representation: str


def cases_for(capture: str) -> tuple[SuiteCase, ...]:
    """Every manifest case in one capture mode, with a stable id and canary."""
    out = []
    for case in load_cases():
        if case.capture.value != capture:
            continue
        case_id = case.identity
        out.append(
            SuiteCase(
                case_id=case_id,
                canary=canary_for(SUITE_STATE, case_id),
                leaf=case.leaf,
                placement=case.placement,
                branch=case.branch,
                detector=case.detector,
                event=case.event,
                capture=case.capture.value,
                operation=case.operation,
                grant=case.grant,
                representation=case.representation,
            )
        )
    return tuple(out)


def emitted_for(case: SuiteCase, path: str) -> Emitted:
    return Emitted(
        case_id=case.case_id,
        leaf=case.leaf,
        placement=case.placement,
        branch=case.branch,
        detector=case.detector,
        event=case.event,
        capture=case.capture,
        operation=case.operation,
        grant=case.grant,
        representation=case.representation,
        path=path,
    )


def diagnose(case: SuiteCase, message: str) -> str:
    """Every failure carries the replay identifier and the case id."""
    return f"{message} [{SUITE_STATE.diagnostic()} case={case.case_id}]"


def route_all(emitted: list[Emitted]) -> None:
    check_emitted_are_resolved(emitted)


def require_all(emitted: list[Emitted], required: list[Emitted]) -> None:
    check_required_are_emitted(emitted, required)
