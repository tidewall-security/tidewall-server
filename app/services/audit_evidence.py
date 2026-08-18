"""The internal channel by which a detector reports what it actually matched.

P0-6: Tidewall stores every prompt verbatim and serves it to any viewer. The
fix keeps a *tiered* record instead — type-and-count evidence at viewer level,
exact matched values behind a separate grant, whole prompts behind another.

The middle tier is why this module exists, and it cannot be built from what a
detector already publishes. ``DetectorResult.data`` is an unrestricted dict
shaped for the API response, so deriving stored evidence from it would inherit
whatever any detector happens to put there, now and in future. It also cannot
be rebuilt from offsets against the guard's flattened text, because redaction
rewrites that text as detectors run, so an offset captured at one stage does
not mean the same thing at the next.

So a detector reports its matches explicitly, bound to the original field it
read, at the moment it reads it, and every match is verified against that
original before it is accepted.

## The three rules this module actually enforces

**Capture is atomic per detector run.** A detector submits its matches inside
``collector.capture(...)``; if any one of them fails validation, the whole
batch is discarded. Validating match-by-match was not enough — earlier good
matches survived a later bad one, leaving a partial capture that reads as a
complete one.

**Offsets and originals do not outlive the collector.** They exist to prove
provenance and are destroyed by ``finalize()``, which also prevents reuse.
Returning offset-free groups was not enough on its own: the collector still
held every original string and coordinate, reachable through ``repr`` and
pickling.

**Bounds fail closed, measured on what will actually be stored.** The size
limit is checked against canonical JSON bytes, because a limit that cannot
measure the thing it bounds is decoration. Overflow invalidates the entire
capture rather than truncating — a truncated set reads as complete, and
nothing in the record would say it was cut.

## Conventions

``start``/``end`` are **Python code-point indices** into the original field.
A producer using byte or UTF-16 offsets will fail validation rather than
record a wrong span, which is the intended outcome.

Errors never interpolate caller-controlled strings, coordinates, or content.
This code runs where an operator's logs can see it, and the values in question
are exactly what the product exists to protect.
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Literal

# Overflow fails capture closed rather than truncating.
MAX_MATCH_GROUPS = 100
MAX_OCCURRENCES_PER_GROUP = 100
MAX_VALUE_BYTES = 8 * 1024
MAX_MATCHES_JSON_BYTES = 256 * 1024
# Collection-time ceiling. Without it a buggy or hostile detector can retain
# unbounded values and originals before any aggregate limit is reached.
MAX_MATCHES_COLLECTED = MAX_MATCH_GROUPS * MAX_OCCURRENCES_PER_GROUP

# Persistence contract. Step 4 must store exactly the bytes canonical_json()
# produces, not re-serialise the dicts: the size limit is measured on these
# bytes, and a different serialiser would bound something else.
MATCHES_SCHEMA_VERSION = 1

SOURCE_KINDS = ("message", "tool")
SOURCE_FIELDS = ("content", "name", "description", "parameters")
_MAX_IDENTIFIER_LENGTH = 64

SourceKind = Literal["message", "tool"]
SourceField = Literal["content", "name", "description", "parameters"]


class EvidenceError(ValueError):
    """A match that cannot be trusted as provenance.

    Carries a stable ``code`` and deliberately no content, no coordinates and
    no caller-supplied strings.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


def _check_identifier(value: object, code: str) -> str:
    """Reject anything that is not a plain internal identifier.

    Detector names, match types and rule IDs are interpolated into errors and
    stored, so a value carrying protected content or arbitrary text must not
    get that far. ``Literal`` annotations do not validate at runtime.
    """
    if not isinstance(value, str) or not value:
        raise EvidenceError(code, "must be a non-empty string")
    if len(value) > _MAX_IDENTIFIER_LENGTH:
        raise EvidenceError(code, "is too long")
    # ASCII deliberately: str.isalnum() accepts Cyrillic and fullwidth
    # characters, so "pii" and "\u0440\u0456\u0456" would be different identifiers that look
    # identical. These become persistence and authorization discriminators.
    if not all(("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9") or c in "_-." for c in value):
        raise EvidenceError(code, "contains characters that are not allowed in an identifier")
    return value


def _utf8_length(value: str, code: str) -> int:
    """Byte length, refusing strings that are not valid Unicode scalars.

    An unpaired surrogate passes a slice comparison and then explodes inside
    ``encode``. That must be a fail-closed EvidenceError, not an incidental
    UnicodeEncodeError escaping the contract.
    """
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise EvidenceError(code, "is not valid Unicode (unpaired surrogate)") from None


@dataclass(frozen=True)
class SourceRef:
    """Which original field a match came from.

    Provenance is part of identity: the same address in a user's question and
    in a tool's response are different findings, and merging them would erase
    which one leaked.
    """

    kind: SourceKind
    index: int
    field: SourceField
    role: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in SOURCE_KINDS:
            raise EvidenceError("source.kind.invalid")
        if self.field not in SOURCE_FIELDS:
            raise EvidenceError("source.field.invalid")
        if not isinstance(self.index, int) or isinstance(self.index, bool) or self.index < 0:
            raise EvidenceError("source.index.invalid")
        if self.role is not None:
            _check_identifier(self.role, "source.role.invalid")


@dataclass(frozen=True)
class ExactMatch:
    """One value a detector matched, bound to where it read it.

    ``start``/``end`` are code-point indices into the original, unmodified
    field — never the guard's concatenated text and never a partially redacted
    version. They are used to verify the match and then destroyed.
    """

    detector: str
    match_type: str
    source: SourceRef
    value: str
    start: int
    end: int
    rule_id: str | None = None

    def __post_init__(self) -> None:
        _check_identifier(self.detector, "match.detector.invalid")
        _check_identifier(self.match_type, "match.type.invalid")
        if self.rule_id is not None:
            _check_identifier(self.rule_id, "match.rule_id.invalid")
        for coord in (self.start, self.end):
            if not isinstance(coord, int) or isinstance(coord, bool):
                raise EvidenceError("match.offset.invalid")
        if not isinstance(self.source, SourceRef):
            raise EvidenceError("match.source.invalid")


@dataclass(frozen=True)
class MatchGroup:
    """Exact duplicates of one value in one place, counted.

    Frozen and offset-free. Grouping is deliberately narrow: two matches merge
    only when detector, type, rule, provenance *and* value are all identical.
    Overlapping matches stay separate, because collapsing them would discard
    why each detector fired, which is what an analyst reads this to find out.
    """

    detector: str
    match_type: str
    source: SourceRef
    value: str
    rule_id: str | None
    occurrences: int

    def as_storable(self) -> dict[str, Any]:
        """The canonical form that will be persisted. Never includes offsets.

        Source provenance is included deliberately: without it the same value
        found in a user question and in a tool response are indistinguishable,
        and which one leaked is usually the question being asked.
        """
        return {
            "detector": self.detector,
            "match_type": self.match_type,
            "rule_id": self.rule_id,
            "source": {
                "kind": self.source.kind,
                "index": self.source.index,
                "field": self.source.field,
                "role": self.source.role,
            },
            "value": self.value,
            "occurrences": self.occurrences,
        }


def canonical_json(groups: list[MatchGroup]) -> str:
    """The exact representation that gets stored, so the limit can measure it.

    Persistence must write these bytes rather than re-serialising the dicts.
    A JSON column with its own serialiser would produce different whitespace,
    escaping or key order, and the size limit would then be bounding something
    other than what is stored.
    """
    payload = {"schema_version": MATCHES_SCHEMA_VERSION, "matches": [g.as_storable() for g in groups]}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def validate_match(match: ExactMatch, original: str) -> None:
    """Check a match against the field it claims to come from.

    The byte-for-byte comparison is the point. A detector reporting a value
    that is no longer at the offsets it reported has read something else — a
    transformed copy, a stale buffer, a different message — and cannot be
    trusted as provenance for any of them.
    """
    if not isinstance(match.value, str) or not match.value:
        raise EvidenceError("match.value.empty")
    if not (0 <= match.start < match.end <= len(original)):
        # No coordinates in the message: they are a reconstruction aid.
        raise EvidenceError("match.span.out_of_range")
    if original[match.start : match.end] != match.value:
        raise EvidenceError("match.span.stale", "the recorded span no longer contains the recorded value")
    if _utf8_length(match.value, "match.value.invalid_unicode") > MAX_VALUE_BYTES:
        raise EvidenceError("match.value.too_large")
    if unicodedata.normalize("NFC", match.value) != match.value:
        # Non-canonical forms let one value be stored under several
        # representations, which silently defeats grouping and comparison.
        # NFC, not NFKC: NFKC would collapse compatibility-distinct source
        # text and claim an equality the proven slice does not have.
        raise EvidenceError("match.value.not_canonical")


def _sort_key(group: MatchGroup) -> tuple:
    """Total order over everything that distinguishes a group.

    An incomplete key leaves ties broken by submission order, so the same
    input could serialise two different ways for no reason.
    """
    return (
        group.source.kind,
        group.source.index,
        group.source.field,
        group.source.role is not None,
        group.source.role or "",
        group.detector,
        group.match_type,
        group.rule_id is not None,
        group.rule_id or "",
        group.value,
    )


@dataclass
class MatchCollector:
    """Gathers matches during a scan, holding the originals to validate against.

    Sensitive state is excluded from ``repr`` and pickling is refused: the
    collector holds every original field and every coordinate, and the point of
    destroying them at ``finalize()`` is lost if they can be serialised out.
    """

    _originals: dict[SourceRef, str] = field(default_factory=dict, repr=False)
    _matches: list[ExactMatch] = field(default_factory=list, repr=False)
    _finalized: bool = field(default=False, repr=False)
    _capture_open: bool = field(default=False, repr=False)

    def __getstate__(self) -> None:
        raise EvidenceError("collector.not_serializable", "the collector holds original content and offsets")

    def register_source(self, source: SourceRef, original: str) -> None:
        """Record a field as it arrived, before any detector runs."""
        if self._finalized:
            raise EvidenceError("collector.finalized")
        if not isinstance(original, str):
            raise EvidenceError("source.original.invalid")
        existing = self._originals.get(source)
        if existing is not None and existing != original:
            # Overwriting would rebind already-accepted matches to text they
            # were never checked against.
            raise EvidenceError("source.conflicting_registration")
        self._originals[source] = original

    @contextmanager
    def capture(self, detector: str) -> Iterator[_DetectorCapture]:
        """Stage one detector's matches, committing only if all of them pass.

        Validating one at a time let earlier good matches survive a later bad
        one, so a detector that went wrong part-way still contributed a partial
        set — indistinguishable, once stored, from a complete one.

        Captures do not nest and cannot overlap finalization. Allowing either
        made the transaction boundary depend on call order: an inner capture
        could commit while its outer block rolled back, and calling finalize()
        from inside a block left a committed match in a collector that had
        already destroyed the originals it would be validated against.
        """
        if self._finalized:
            raise EvidenceError("collector.finalized")
        if self._capture_open:
            raise EvidenceError("collector.capture_already_open")
        _check_identifier(detector, "match.detector.invalid")

        staged = _DetectorCapture(detector, self)
        self._capture_open = True
        try:
            yield staged
        except BaseException:
            # Any failure discards the batch, not only EvidenceError: an
            # exception raised by the caller mid-batch leaves exactly the same
            # partial set as a validation failure.
            raise
        else:
            # State can have changed inside the block; the commit has to look
            # again rather than trust what was true on entry.
            if self._finalized:
                raise EvidenceError("collector.finalized")
            for match in staged._staged:
                if match.detector != detector:
                    raise EvidenceError("match.detector.mismatch")
            if len(self._matches) + len(staged._staged) > MAX_MATCHES_COLLECTED:
                raise EvidenceError("collector.too_many_matches")
            self._matches.extend(staged._staged)
        finally:
            staged._closed = True
            self._capture_open = False

    def finalize(self) -> list[MatchGroup]:
        """Group the matches and destroy the originals and offsets.

        Destructive by design: after this the collector holds no content, and
        cannot be reused to produce a second, differently-bounded result.
        """
        if self._finalized:
            raise EvidenceError("collector.finalized")
        if self._capture_open:
            raise EvidenceError("collector.capture_already_open")

        # One-shot from here regardless of outcome. Clearing only on success
        # left a fully populated collector behind every failure — the caller
        # could retry, add sources, or simply keep it, which is the opposite of
        # "overflow invalidates the entire capture".
        self._finalized = True
        groups: list[MatchGroup] = []
        try:
            return self._build_groups(groups)
        finally:
            self._originals.clear()
            self._matches.clear()

    def _build_groups(self, groups: list[MatchGroup]) -> list[MatchGroup]:
        grouped: dict[tuple, list[Any]] = {}
        for match in self._matches:
            original = self._originals.get(match.source)
            if original is None:
                raise EvidenceError("source.unregistered")
            validate_match(match, original)

            key = (
                match.detector,
                match.match_type,
                match.rule_id,
                match.source,
                match.value,
            )
            existing = grouped.get(key)
            if existing is None:
                if len(grouped) >= MAX_MATCH_GROUPS:
                    raise EvidenceError("capture.too_many_groups")
                grouped[key] = [match, 1]
            else:
                if existing[1] >= MAX_OCCURRENCES_PER_GROUP:
                    raise EvidenceError("capture.too_many_occurrences")
                existing[1] += 1

        groups.extend(
            MatchGroup(
                detector=m.detector,
                match_type=m.match_type,
                source=m.source,
                value=m.value,
                rule_id=m.rule_id,
                occurrences=count,
            )
            for m, count in grouped.values()
        )
        groups.sort(key=_sort_key)

        if len(canonical_json(groups).encode("utf-8")) > MAX_MATCHES_JSON_BYTES:
            # Empty the list the caller would otherwise reach through this
            # frame: an exception keeps its traceback, and the traceback keeps
            # the locals, so simply raising would hand back the oversized
            # result it is refusing to return.
            groups.clear()
            raise EvidenceError("capture.serialized_too_large")

        return groups


@dataclass
class _DetectorCapture:
    """One detector's staged matches. Nothing here is committed until the
    surrounding ``capture()`` block exits without error."""

    detector: str
    _collector: MatchCollector = field(repr=False)
    _staged: list[ExactMatch] = field(default_factory=list, repr=False)
    _closed: bool = field(default=False, repr=False)

    def add(self, match: ExactMatch) -> None:
        # Continuing to accept matches after the block exits produced a
        # plausible partial capture: they validated, they appended, and the
        # commit had already run, so they were silently never stored.
        if self._closed:
            raise EvidenceError("capture.closed")
        if match.detector != self.detector:
            raise EvidenceError("match.detector.mismatch")
        original = self._collector._originals.get(match.source)
        if original is None:
            raise EvidenceError("source.unregistered")
        validate_match(match, original)
        if len(self._staged) >= MAX_MATCHES_COLLECTED:
            raise EvidenceError("collector.too_many_matches")
        self._staged.append(match)
