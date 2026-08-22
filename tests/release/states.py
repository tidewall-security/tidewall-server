"""Deriving the component STATE domain from what is observed, not asserted.

Task 2's registry carries component NAMES. The plan requires
BEHAVIOUR-CHANGING STATES -- enabled/disabled, success/failure, short-circuit
-- and marking states is cheap while choosing which ones matter is not:
a state belongs in the domain only if reaching it ALTERS AN OBSERVABLE SURFACE.

That cannot be settled by reading the source, because a state that changes an
internal variable and nothing else looks identical in a diff to one that
changes the verdict. It is settled by running the same code twice, differing
only in which state is reached, and comparing the surfaces.

THE SURFACE, for a scan, is the ScanResult a caller receives: `blocked`,
`transformed`, `guard_output_text`, `detectors`, `summary_parts`, `failures`
and `partial`. A state that leaves every one of those identical has not been
shown to change behaviour, and marking it does not make it so.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: The fields a caller can actually see. Comparing fewer of these makes a
#: state look inert; comparing an internal attribute makes every state look
#: behaviour-changing.
SURFACE_FIELDS: tuple[str, ...] = (
    "blocked",
    "transformed",
    "guard_output_text",
    "detectors",
    "summary_parts",
    "failures",
    "partial",
)


class NotBehaviourChanging(Exception):
    """Two runs reached different states and produced identical surfaces."""


class StatesNotDistinct(Exception):
    """The two runs did not actually reach different states."""


@dataclass(frozen=True)
class Surface:
    """One run's observable result, reduced to comparable values."""

    values: dict[str, str]

    @classmethod
    def of(cls, result: Any) -> Surface:
        return cls(values={f: repr(getattr(result, f, None)) for f in SURFACE_FIELDS})

    def differences(self, other: Surface) -> dict[str, tuple[str, str]]:
        return {f: (self.values[f], other.values[f]) for f in SURFACE_FIELDS if self.values[f] != other.values[f]}


def derive(
    *,
    state: str,
    with_state: tuple[set[str], Any],
    without_state: tuple[set[str], Any],
) -> dict[str, tuple[str, str]]:
    """Return the surface differences a state accounts for.

    Refuses two ways, because both failures look like a pass:

      * if the two runs did not actually differ in whether `state` was
        reached, any surface difference is evidence about something else;
      * if they did and the surfaces are identical, the state is not
        behaviour-changing on this evidence, and saying so is the point.
    """
    reached_states, reached_result = with_state
    other_states, other_result = without_state

    if state not in reached_states:
        raise StatesNotDistinct(f"{state} was not reached by the run that should reach it")
    if state in other_states:
        raise StatesNotDistinct(f"{state} was reached by the control run too")

    diff = Surface.of(reached_result).differences(Surface.of(other_result))
    if not diff:
        raise NotBehaviourChanging(
            f"{state} altered no surface field; it is a marked location, not a " "behaviour-changing state"
        )
    return diff
