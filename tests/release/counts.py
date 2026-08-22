"""The two count rules, and the historical pass condition stated in full.

Naming a rule is not stating it. This module states both, and the historical
condition that the earlier drafts left as a phrase:

CAPTURE-OFF
    Expected count is ZERO. Any occurrence in any artifact fails -- live
    image, WAL frame, journal page, freelist or freeblock alike. There is no
    "it was only historical" excuse when capture is off, because nothing was
    ever supposed to write it.

CAPTURE-ON
    EXACT CARDINALITY against the CHECKPOINTED AND VACUUMED canonical live
    image, taken from the copy map. Not "at least one": a unique column holds
    its value twice, and both an under-count and an over-count are failures.
    The image must be checkpointed (so WAL frames are folded in) and vacuumed
    (so freed pages and freeblocks are gone) or the count measures history
    rather than state.

HISTORICAL ARTIFACTS -- WAL frames, journal pages, freelist pages, freeblocks
    An occurrence is permitted ONLY when both hold:

      1. the artifact belongs to the SAME DATABASE FILE as the live path;
      2. that value's LIVE occurrence at its declared path resolves REQUIRED
         or ALLOWED-BOUNDED.

    An occurrence of a value whose live count is ZERO fails: nothing live
    justifies the residue. An occurrence whose live path resolves FORBIDDEN
    fails: history does not launder a value that was never allowed to rest
    there.

    HISTORICAL DUPLICATES ARE NOT COUNTED. A value legitimately live may
    appear in any number of superseded page images -- how many is an artifact
    of page churn, not of behaviour. They are permitted or they are not; there
    is no cardinality to assert.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from tests.release.attribution import expected_locations
from tests.release.corpus import ArtifactSet
from tests.release.occurrences import Rule

#: Artifact kinds whose contents are superseded state rather than live state.
HISTORICAL_KINDS: frozenset[str] = frozenset({"wal", "journal", "shm"})


class CountViolation(Exception):
    """A count rule was broken. Carries which rule and what was measured."""


@dataclass(frozen=True)
class Measured:
    """What a scan actually found, split by whether it is live or historical."""

    live: dict[str, int]
    historical: dict[str, int]

    @property
    def live_total(self) -> int:
        return sum(self.live.values())

    @property
    def historical_total(self) -> int:
        return sum(self.historical.values())


def canonical_live_image(db: Path, into: Path) -> Path:
    """A checkpointed and vacuumed copy: state with no history in it.

    VACUUM INTO writes a fresh database containing only live content -- no WAL
    frames, no freelist, no freeblocks. Counting against anything else counts
    history, and the count stops being an oracle for what the code did.
    """
    into.parent.mkdir(parents=True, exist_ok=True)
    if into.exists():
        into.unlink()
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        conn.execute("VACUUM INTO ?", (str(into),))
    finally:
        conn.close()
    return into


def measure(captured: ArtifactSet, needle: bytes) -> Measured:
    """Split a byte scan into live and historical occurrences."""
    live: dict[str, int] = {}
    historical: dict[str, int] = {}
    for artifact in captured.artifacts:
        data = artifact.data
        if not data:
            continue
        count = data.count(needle)
        if not count:
            continue
        key = f"{artifact.moment}:{artifact.kind}"
        if artifact.kind in HISTORICAL_KINDS:
            historical[key] = count
        else:
            live[key] = count
    return Measured(live=live, historical=historical)


def check_capture_off(measured: Measured) -> None:
    """Expected count zero, in every artifact, historical included."""
    found = {**measured.live, **measured.historical}
    if found:
        raise CountViolation(f"capture-off expects zero occurrences, found {found}")


def check_capture_on(
    conn: sqlite3.Connection,
    path: tuple[str, str],
    canonical_count: int,
) -> None:
    """Exact cardinality against the canonical live image, from the copy map.

    `canonical_count` is the byte-scan total over the checkpointed-and-vacuumed
    image. It must equal the copy map's prediction exactly.
    """
    predicted = sum(expected_locations(conn, path).values())
    if canonical_count != predicted:
        direction = "under" if canonical_count < predicted else "over"
        raise CountViolation(
            f"capture-on {direction}-count for {path[0]}.{path[1]}: "
            f"canonical image holds {canonical_count}, copy map predicts {predicted}"
        )


def check_historical(
    measured: Measured,
    *,
    live_rule: Rule,
    live_count: int,
    same_database_file: bool,
) -> None:
    """The historical pass condition, in full.

    Duplicates are not counted -- only whether any occurrence is permitted.
    """
    if not measured.historical:
        return

    where = sorted(measured.historical)
    if not same_database_file:
        raise CountViolation(f"historical occurrence in an artifact of a different database file: {where}")
    if live_count == 0:
        raise CountViolation(f"historical occurrence of a value with no live occurrence: {where}")
    if live_rule is Rule.FORBIDDEN:
        raise CountViolation(f"historical occurrence of a value FORBIDDEN at its live path: {where}")
    if live_rule not in (Rule.REQUIRED, Rule.ALLOWED_BOUNDED):
        raise CountViolation(f"historical occurrence under unhandled rule {live_rule}: {where}")
