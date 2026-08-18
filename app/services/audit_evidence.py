"""The internal channel by which a detector reports what it actually matched.

P0-6: Tidewall stores every prompt verbatim and serves it to any viewer. The
fix keeps a *tiered* record instead — type-and-count evidence at viewer level,
exact matched values behind a separate grant, whole prompts behind another.

The middle tier is why this module exists, and it cannot be built from what a
detector already publishes. ``DetectorResult.data`` is an unrestricted dict
shaped for the API response; deriving stored evidence from it would mean
inheriting whatever any detector happens to put there, now and in future. It
also cannot be rebuilt from offsets against the guard's flattened text, because
redaction rewrites that text as detectors run, so an offset captured at one
stage does not mean the same thing at the next.

So a detector reports its matches explicitly, bound to the original field it
read, at the moment it reads it. Every match is validated against that original
string at collection time: if the recorded span does not still contain exactly
the recorded value, the capture fails rather than guessing.

Two rules hold everywhere below:

- **Offsets never leave this process.** They exist to prove provenance during
  validation and are discarded once matches are grouped. They are not stored,
  returned, exported or logged — a start/end pair against a known field is a
  reconstruction aid for anyone who later obtains a fragment.
- **Nothing falls back to public payloads.** A failed validation drops that
  detector's exact-match capture. It never reaches for ``data`` instead, which
  would reintroduce exactly the uncontrolled surface this replaces.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Literal

# Bounds. Overflow fails capture closed rather than truncating, because a
# truncated set of exact matches reads as a complete one to whoever later
# inspects it, and there is no way to tell from the record that it was cut.
MAX_MATCH_GROUPS = 100
MAX_OCCURRENCES_PER_GROUP = 100
MAX_VALUE_BYTES = 8 * 1024
MAX_MATCHES_JSON_BYTES = 256 * 1024

SourceKind = Literal["message", "tool"]
SourceField = Literal["content", "name", "description", "parameters"]


class EvidenceError(ValueError):
    """A match that cannot be trusted as provenance.

    Raised at collection, never swallowed into a partial result: a match whose
    span no longer contains its value means the detector and the text have
    diverged, and the safe response is to record nothing for that detector
    rather than something plausible.
    """


@dataclass(frozen=True)
class SourceRef:
    """Which original field a match came from.

    Identical values found in different messages are different findings — the
    same address in the user's own question and in a tool's response mean
    different things — so provenance is part of identity, not decoration.
    """

    kind: SourceKind
    index: int
    field: SourceField
    role: str | None = None

    def __post_init__(self) -> None:
        if self.index < 0:
            raise EvidenceError(f"source index must not be negative, got {self.index}")


@dataclass(frozen=True)
class ExactMatch:
    """One value a detector matched, bound to where it read it.

    ``start``/``end`` are relative to the original, unmodified field — not to
    the guard's concatenated text, and not to any partially redacted version.
    They are used to verify the match and then discarded.
    """

    detector: str
    match_type: str
    source: SourceRef
    value: str
    start: int
    end: int
    rule_id: str | None = None


@dataclass
class MatchGroup:
    """Exact duplicates of one value in one place, counted.

    Grouping is deliberately narrow. Two matches merge only when detector,
    type, rule, provenance *and* value are all identical. Overlapping matches
    — from one detector or several — stay separate, because collapsing them
    would discard why each detector fired, which is the thing an analyst is
    reading this to find out.
    """

    detector: str
    match_type: str
    source: SourceRef
    value: str
    rule_id: str | None = None
    occurrences: int = 1


def validate_match(match: ExactMatch, original: str) -> None:
    """Check a match against the field it claims to come from.

    The byte-for-byte comparison is the point. A detector that reports a value
    which is no longer at the offsets it reported has read something else — a
    transformed copy, a different message, a stale buffer — and its matches
    cannot be trusted as provenance for any of them.
    """
    if not isinstance(match.value, str) or not match.value:
        raise EvidenceError(f"{match.detector}: match value must be a non-empty string")
    if not (0 <= match.start < match.end <= len(original)):
        raise EvidenceError(
            f"{match.detector}: span {match.start}:{match.end} is outside the "
            f"{len(original)}-character source field"
        )
    if original[match.start : match.end] != match.value:
        # Deliberately does not report either string: this runs on a path that
        # may end up in an operator's log, and the mismatch is between two
        # pieces of exactly the content being protected.
        raise EvidenceError(
            f"{match.detector}: the recorded span no longer contains the recorded value; "
            f"refusing to record it as provenance"
        )
    if len(match.value.encode("utf-8")) > MAX_VALUE_BYTES:
        raise EvidenceError(f"{match.detector}: match value exceeds {MAX_VALUE_BYTES} bytes")
    if unicodedata.normalize("NFC", match.value) != match.value:
        # Non-canonical forms let the same value be stored under several
        # representations, which defeats grouping and comparison later.
        raise EvidenceError(f"{match.detector}: match value is not canonical (NFC) Unicode")


def group_matches(matches: list[ExactMatch], originals: dict[SourceRef, str]) -> list[MatchGroup]:
    """Validate, group and order matches, discarding offsets.

    Ordering is deterministic — by provenance, then position, then detector —
    so the stored record does not vary between runs over the same input, which
    would make two audit records look different for no reason.
    """
    for match in matches:
        original = originals.get(match.source)
        if original is None:
            raise EvidenceError(f"{match.detector}: no original field recorded for {match.source}")
        validate_match(match, original)

    ordered = sorted(
        matches,
        key=lambda m: (m.source.kind, m.source.index, m.source.field, m.start, m.end, m.detector, m.match_type),
    )

    grouped: dict[tuple, MatchGroup] = {}
    for match in ordered:
        key = (
            match.detector,
            match.match_type,
            match.rule_id,
            match.source.kind,
            match.source.index,
            match.source.field,
            match.source.role,
            match.value,
        )
        existing = grouped.get(key)
        if existing is None:
            if len(grouped) >= MAX_MATCH_GROUPS:
                raise EvidenceError(f"more than {MAX_MATCH_GROUPS} distinct matches; refusing to record a partial set")
            grouped[key] = MatchGroup(
                detector=match.detector,
                match_type=match.match_type,
                source=match.source,
                value=match.value,
                rule_id=match.rule_id,
            )
        else:
            if existing.occurrences >= MAX_OCCURRENCES_PER_GROUP:
                raise EvidenceError(
                    f"{match.detector}: more than {MAX_OCCURRENCES_PER_GROUP} occurrences of one value; "
                    f"refusing to record a partial count"
                )
            existing.occurrences += 1

    return list(grouped.values())


@dataclass
class MatchCollector:
    """Gathers matches during a scan, holding the originals to validate against.

    The scanner registers each original field before any detector runs, so
    validation always compares against the text as it arrived rather than as it
    currently is.
    """

    _originals: dict[SourceRef, str] = field(default_factory=dict)
    _matches: list[ExactMatch] = field(default_factory=list)

    def register_source(self, source: SourceRef, original: str) -> None:
        self._originals[source] = original

    def add(self, match: ExactMatch) -> None:
        original = self._originals.get(match.source)
        if original is None:
            raise EvidenceError(f"{match.detector}: {match.source} was never registered as a source")
        validate_match(match, original)
        self._matches.append(match)

    def grouped(self) -> list[MatchGroup]:
        return group_matches(self._matches, self._originals)
