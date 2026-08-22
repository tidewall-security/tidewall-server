"""The state needed to reproduce a run. A SEED IS NOT ENOUGH.

A recorded seed reconstructs the canaries and nothing else. Reproducing a
failure also needs what the run was executed AGAINST, and each of these has
changed a result at least once:

  * DETECTOR CONFIGURATION -- which detectors were enabled, and with what;
  * THE COMPONENT/SUB-PATH SCHEDULE -- which marked states were reachable;
  * BRANCH SCHEDULING -- which branch each case exercised;
  * FIXTURE AND DATABASE STATE -- schema revision and seeded rows;
  * BROWSER STATE -- storage and console carried between navigations.

All of it is recorded as concrete values, and the whole record is
content-addressed so a diagnostic can carry one short identifier that
reconstructs it. THE IDENTIFIER IS IN EVERY FAILURE MESSAGE: a run artifact
nobody reads is not a reproduction aid.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class ReplayState:
    """Everything a rerun needs, as values rather than references."""

    seed: int
    detector_config: dict[str, dict]
    component_schedule: tuple[str, ...]
    branch_schedule: tuple[str, ...]
    schema_revision: str
    seeded_rows: tuple[tuple[str, int], ...]
    browser_state: dict[str, str] = field(default_factory=dict)

    def canonical(self) -> str:
        """A stable serialisation. Sorted, so key order cannot change the id."""
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), default=list)

    @property
    def identifier(self) -> str:
        return hashlib.sha256(self.canonical().encode()).hexdigest()[:16]

    def diagnostic(self) -> str:
        """The line every failure carries."""
        return f"replay={self.identifier} seed={self.seed}"


def canary_for(state: ReplayState, case_id: str) -> str:
    """A deterministic canary: same state and case id, same value.

    Derived from the WHOLE state, not the seed alone, so a run whose detector
    configuration differs cannot silently reuse another run's canaries and
    report a matching signature.
    """
    digest = hashlib.sha256(f"{state.identifier}:{case_id}".encode()).hexdigest()
    return f"CANARY-{digest[:16].upper()}"


class ReplayMismatch(Exception):
    """A run was compared against a record of a different state."""


def require_same_state(recorded: ReplayState, actual: ReplayState) -> None:
    if recorded.identifier != actual.identifier:
        differing = [key for key in asdict(recorded) if asdict(recorded)[key] != asdict(actual)[key]]
        raise ReplayMismatch(f"replay {recorded.identifier} != {actual.identifier}; differing: {differing}")
