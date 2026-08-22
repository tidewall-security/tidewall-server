"""The resolver in the consumer path, in BOTH directions.

One direction cannot catch the other's failure, and that is not a symmetry
argument -- it is a structural fact:

  EMITTED -> RESOLVED catches an occurrence that reached an assertion with no
  rule behind it. It cannot catch an ABSENT `REQUIRED` occurrence, because
  nothing was emitted, so nothing was routed, so nothing was unresolved. A
  suite with only this direction reports green when a required value silently
  stopped being written.

  REQUIRED -> EMITTED catches exactly that. It cannot catch an occurrence at a
  surface no rule covers, because the required set says nothing about it.

So both run, over the same emitted multiset.

`FORBIDDEN` applies BY DEFAULT over the enumerated surfaces: an occurrence at
a surface in the domain with no more specific rule is forbidden, not
unclassified. `ALLOWED-BOUNDED` is optional -- it need not occur -- but is
CONFINED to the paths it enumerates, so the same value at an unlisted sibling
path fails.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from tests.release.occurrences import ROWS, Ambiguous, NoRule, OutOfDomain, Rule, resolve


class UnresolvedOccurrence(Exception):
    """An occurrence reached an assertion without a rule behind it."""


class RequiredOccurrenceMissing(Exception):
    """A REQUIRED row was never emitted."""


class ForbiddenOccurrence(Exception):
    """An occurrence reached a surface where it is forbidden."""


@dataclass(frozen=True)
class Emitted:
    """One concrete occurrence a collector produced."""

    case_id: str
    leaf: str
    placement: str
    branch: str
    detector: str
    event: str
    capture: str
    operation: str
    grant: str
    representation: str
    path: str

    def axes(self) -> dict:
        return {
            "leaf": self.leaf,
            "placement": self.placement,
            "branch": self.branch,
            "detector": self.detector,
            "event": self.event,
            "capture": self.capture,
            "operation": self.operation,
            "grant": self.grant,
            "representation": self.representation,
            "path": self.path,
        }

    def signature(self) -> tuple:
        return (self.case_id, self.path, self.representation)


def route(emitted: Emitted, rows=ROWS):
    """Send one occurrence through the REAL resolver.

    Every failure mode is distinct and none is swallowed: an occurrence with
    no rule, with two rules, or outside the domain each has a different fix.

    `rows` is threaded rather than fixed because the shipped matrix carries a
    catch-all row -- FORBIDDEN by default over the enumerated surfaces -- so
    nothing ever resolves to NoRule against it. Exercising the zero-match and
    two-match failures needs a row set that can produce them.
    """
    try:
        return resolve(**emitted.axes(), rows=rows)
    except OutOfDomain:
        raise
    except (NoRule, Ambiguous) as exc:
        raise UnresolvedOccurrence(f"{emitted.case_id} at {emitted.path}: {type(exc).__name__}: {exc}") from exc


def check_emitted_are_resolved(emitted: list[Emitted], rows=ROWS) -> list:
    """Direction 1. Every emitted occurrence carries a resolution."""
    resolutions = []
    for occurrence in emitted:
        row = route(occurrence, rows)
        if row.rule is Rule.FORBIDDEN:
            raise ForbiddenOccurrence(f"{occurrence.case_id}: FORBIDDEN occurrence reached {occurrence.path}")
        resolutions.append(row)
    return resolutions


def check_required_are_emitted(emitted: list[Emitted], required: list[Emitted]) -> None:
    """Direction 2. Every applicable REQUIRED row appears in the emitted set.

    Compared as a MULTISET: a required occurrence expected twice and emitted
    once is a failure, and a set comparison reports agreement.
    """
    produced = Counter(e.signature() for e in emitted)
    expected = Counter(r.signature() for r in required)

    missing = expected - produced
    if missing:
        raise RequiredOccurrenceMissing(
            "REQUIRED occurrences never emitted: " + ", ".join(f"{sig} x{n}" for sig, n in sorted(missing.items()))
        )


def check_allowed_bounded_is_confined(emitted: list[Emitted], enumerated_paths: set[str], rows=ROWS) -> None:
    """ALLOWED-BOUNDED is optional, but only at the paths it enumerates.

    The same value at an unlisted sibling is not covered by the allowance.
    """
    for occurrence in emitted:
        row = route(occurrence, rows)
        if row.rule is Rule.ALLOWED_BOUNDED and occurrence.path not in enumerated_paths:
            raise ForbiddenOccurrence(
                f"{occurrence.case_id}: ALLOWED-BOUNDED value at unlisted path "
                f"{occurrence.path}; enumerated: {sorted(enumerated_paths)}"
            )
