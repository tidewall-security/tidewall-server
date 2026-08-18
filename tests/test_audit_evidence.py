"""The internal exact-match channel (P0-6, step 1).

This decides what exact content gets stored under the middle role tier. If a
match can be recorded without being verified against the text it claims to come
from, whatever ends up in the audit record is unprovenanced — and it is exactly
the content the product exists to protect.

The first version of these tests passed while three invariants were false: a
partial detector capture survived a failed match, the collector retained every
original and offset after grouping, and the serialised size limit was never
enforced. Several tests below exist specifically because of that.
"""

from __future__ import annotations

import pickle
import unicodedata

import pytest

from app.services.audit_evidence import (
    MAX_MATCH_GROUPS,
    MAX_MATCHES_JSON_BYTES,
    MAX_OCCURRENCES_PER_GROUP,
    MAX_VALUE_BYTES,
    EvidenceError,
    ExactMatch,
    MatchCollector,
    MatchGroup,
    SourceRef,
    canonical_json,
)

MSG = SourceRef(kind="message", index=0, field="content", role="user")


def _collector(text: str, source: SourceRef = MSG) -> MatchCollector:
    c = MatchCollector()
    c.register_source(source, text)
    return c


def _m(value: str, start: int, end: int, **kw) -> ExactMatch:
    return ExactMatch(
        detector=kw.pop("detector", "pii"),
        match_type=kw.pop("match_type", "EMAIL_ADDRESS"),
        source=kw.pop("source", MSG),
        value=value,
        start=start,
        end=end,
        **kw,
    )


def _capture(collector: MatchCollector, *matches: ExactMatch, detector: str = "pii") -> None:
    with collector.capture(detector) as batch:
        for m in matches:
            batch.add(m)


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def test_a_match_that_does_not_match_is_refused():
    """A detector reporting a value that is not at the offsets it reported has
    read something else. Recording it would attach provenance to content that
    never had it."""
    collector = _collector("contact alice@example.com please")

    with pytest.raises(EvidenceError) as exc:
        _capture(collector, _m("bob@example.com", 8, 25))

    assert exc.value.code == "match.span.stale"


def test_a_correct_match_is_accepted():
    collector = _collector("contact alice@example.com please")
    _capture(collector, _m("alice@example.com", 8, 25))

    groups = collector.finalize()

    assert len(groups) == 1
    assert groups[0].value == "alice@example.com"
    assert groups[0].occurrences == 1


def test_a_span_outside_the_field_is_refused():
    collector = _collector("short")
    with pytest.raises(EvidenceError) as exc:
        _capture(collector, _m("short", 0, 500))
    assert exc.value.code == "match.span.out_of_range"


def test_an_unregistered_source_is_refused():
    collector = _collector("hello")
    other = SourceRef(kind="tool", index=3, field="description")
    with pytest.raises(EvidenceError) as exc:
        _capture(collector, _m("hello", 0, 5, source=other))
    assert exc.value.code == "source.unregistered"


def test_a_conflicting_re_registration_is_refused():
    """Overwriting would rebind already-accepted matches to text they were
    never checked against."""
    collector = _collector("original text")
    with pytest.raises(EvidenceError) as exc:
        collector.register_source(MSG, "different text")
    assert exc.value.code == "source.conflicting_registration"


def test_an_identical_re_registration_is_allowed():
    collector = _collector("same text")
    collector.register_source(MSG, "same text")  # must not raise


# ---------------------------------------------------------------------------
# Invariant 1: capture is atomic per detector
# ---------------------------------------------------------------------------


def test_a_failed_match_discards_the_whole_detector_batch():
    """The defect the first version had.

    Validating one match at a time let earlier good matches survive a later
    bad one, leaving a partial capture indistinguishable from a complete one
    once stored.
    """
    text = "alice@example.com and bob@example.com"
    collector = _collector(text)

    with pytest.raises(EvidenceError):
        with collector.capture("pii") as batch:
            batch.add(_m("alice@example.com", 0, 17))  # valid
            batch.add(_m("nobody@example.com", 22, 37))  # stale

    assert collector.finalize() == [], "a partial detector capture survived"


def test_one_detector_failing_does_not_discard_another_that_succeeded():
    """Atomicity is per detector run, not global — a broken custom rule should
    not erase what PII legitimately found."""
    text = "alice@example.com and bob@example.com"
    collector = _collector(text)

    _capture(collector, _m("alice@example.com", 0, 17))
    with pytest.raises(EvidenceError):
        _capture(collector, _m("wrong", 22, 37, detector="secrets", match_type="AWS_KEY"), detector="secrets")

    groups = collector.finalize()
    assert [g.detector for g in groups] == ["pii"]


def test_a_match_cannot_be_staged_under_another_detectors_name():
    collector = _collector("hello")
    with pytest.raises(EvidenceError) as exc:
        with collector.capture("pii") as batch:
            batch.add(_m("hello", 0, 5, detector="secrets"))
    assert exc.value.code == "match.detector.mismatch"


# ---------------------------------------------------------------------------
# Invariant 2: offsets and originals do not outlive the collector
# ---------------------------------------------------------------------------


def test_finalize_destroys_the_originals_and_offsets():
    """Returning offset-free groups was not enough on its own: the collector
    still held every original string and coordinate."""
    collector = _collector("my secret is hunter2")
    _capture(collector, _m("hunter2", 13, 20))

    collector.finalize()

    leaked = repr(vars(collector))
    assert "hunter2" not in leaked
    assert "my secret" not in leaked
    assert collector._matches == []
    assert collector._originals == {}


def test_the_collector_cannot_be_reused_after_finalize():
    collector = _collector("text")
    collector.finalize()
    with pytest.raises(EvidenceError) as exc:
        collector.finalize()
    assert exc.value.code == "collector.finalized"


def test_the_collector_repr_does_not_expose_content():
    collector = _collector("my secret is hunter2")
    _capture(collector, _m("hunter2", 13, 20))

    assert "hunter2" not in repr(collector)


def test_the_collector_refuses_to_be_pickled():
    """It holds every original field and coordinate; destroying them at
    finalize is pointless if they can be serialised out beforehand."""
    collector = _collector("my secret is hunter2")
    _capture(collector, _m("hunter2", 13, 20))

    with pytest.raises(EvidenceError) as exc:
        pickle.dumps(collector)
    assert exc.value.code == "collector.not_serializable"


def test_no_offsets_reach_the_stored_form():
    collector = _collector("alice@example.com")
    _capture(collector, _m("alice@example.com", 0, 17))

    stored = collector.finalize()[0].as_storable()

    assert "start" not in json_keys(stored)
    assert "end" not in json_keys(stored)


def json_keys(obj, acc=None):
    acc = acc if acc is not None else set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            acc.add(k)
            json_keys(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            json_keys(v, acc)
    return acc


# ---------------------------------------------------------------------------
# Invariant 3: bounds fail closed, measured on what is stored
# ---------------------------------------------------------------------------


def test_the_serialized_size_limit_is_actually_enforced():
    """It was defined and never referenced — the eleventh produced-but-not-
    consumed value in this codebase."""
    collector = MatchCollector()
    value = "v" * (MAX_VALUE_BYTES - 1)
    per_group = len(value)
    needed = (MAX_MATCHES_JSON_BYTES // per_group) + 2

    for i in range(min(needed, MAX_MATCH_GROUPS)):
        src = SourceRef(kind="message", index=i, field="content", role="user")
        collector.register_source(src, value)
        _capture(collector, _m(value, 0, len(value), source=src))

    if len(canonical_json_for(collector)) > MAX_MATCHES_JSON_BYTES:
        with pytest.raises(EvidenceError) as exc:
            collector.finalize()
        assert exc.value.code == "capture.serialized_too_large"


def canonical_json_for(collector: MatchCollector) -> bytes:
    from app.services.audit_evidence import MatchGroup

    groups = [
        MatchGroup(
            detector=m.detector,
            match_type=m.match_type,
            source=m.source,
            value=m.value,
            rule_id=m.rule_id,
            occurrences=1,
        )
        for m in collector._matches
    ]
    return canonical_json(groups).encode("utf-8")


def test_exactly_at_the_group_limit_succeeds():
    """'More than N fails' does not prove N succeeds."""
    collector = MatchCollector()
    for i in range(MAX_MATCH_GROUPS):
        src = SourceRef(kind="message", index=i, field="content", role="user")
        collector.register_source(src, "value")
        _capture(collector, _m("value", 0, 5, source=src))

    assert len(collector.finalize()) == MAX_MATCH_GROUPS


def test_one_past_the_group_limit_fails_closed():
    collector = MatchCollector()
    for i in range(MAX_MATCH_GROUPS + 1):
        src = SourceRef(kind="message", index=i, field="content", role="user")
        collector.register_source(src, "value")
        _capture(collector, _m("value", 0, 5, source=src))

    with pytest.raises(EvidenceError) as exc:
        collector.finalize()
    assert exc.value.code == "capture.too_many_groups"


def test_too_many_occurrences_fails_rather_than_undercounting():
    value = "secret"
    text = " ".join([value] * (MAX_OCCURRENCES_PER_GROUP + 2))
    collector = _collector(text)
    with collector.capture("pii") as batch:
        pos = 0
        for _ in range(MAX_OCCURRENCES_PER_GROUP + 2):
            start = text.index(value, pos)
            batch.add(_m(value, start, start + len(value)))
            pos = start + len(value)

    with pytest.raises(EvidenceError) as exc:
        collector.finalize()
    assert exc.value.code == "capture.too_many_occurrences"


# ---------------------------------------------------------------------------
# Identity, ordering, Unicode
# ---------------------------------------------------------------------------


def test_the_same_value_in_different_messages_stays_separate():
    first = SourceRef(kind="message", index=0, field="content", role="user")
    second = SourceRef(kind="message", index=1, field="content", role="assistant")
    collector = MatchCollector()
    collector.register_source(first, "alice@example.com")
    collector.register_source(second, "alice@example.com")

    _capture(
        collector,
        _m("alice@example.com", 0, 17, source=first),
        _m("alice@example.com", 0, 17, source=second),
    )

    assert len(collector.finalize()) == 2


def test_overlapping_matches_from_different_detectors_stay_separate():
    text = "key=AKIAIOSFODNN7EXAMPLE"
    collector = _collector(text)
    _capture(collector, _m("AKIAIOSFODNN7EXAMPLE", 4, 24, detector="secrets", match_type="AWS_KEY"), detector="secrets")
    _capture(
        collector,
        _m("AKIAIOSFODNN7EXAMPLE", 4, 24, detector="custom_entity", match_type="CUSTOM", rule_id="r1"),
        detector="custom_entity",
    )

    assert len(collector.finalize()) == 2


def test_ordering_is_stable_when_sort_keys_would_otherwise_tie():
    """The first sort key stopped at match_type, so groups differing only by
    rule_id were ordered by submission and could serialise two ways."""

    def build(rule_order):
        text = "abc"
        c = _collector(text)
        for rule in rule_order:
            _capture(
                c,
                _m("abc", 0, 3, detector="custom_entity", match_type="CUSTOM", rule_id=rule),
                detector="custom_entity",
            )
        return canonical_json(c.finalize())

    assert build(["r1", "r2"]) == build(["r2", "r1"])


def test_non_canonical_unicode_is_refused():
    decomposed = unicodedata.normalize("NFD", "café")
    assert decomposed != "café"
    collector = _collector(f"visit {decomposed} now")

    with pytest.raises(EvidenceError) as exc:
        _capture(collector, _m(decomposed, 6, 6 + len(decomposed)))
    assert exc.value.code == "match.value.not_canonical"


def test_an_unpaired_surrogate_is_an_evidence_error_not_a_unicode_error():
    """It passes the slice comparison and then explodes inside encode()."""
    bad = "\ud800"
    collector = _collector(f"x{bad}y")

    with pytest.raises(EvidenceError) as exc:
        _capture(collector, _m(bad, 1, 2))
    assert exc.value.code == "match.value.invalid_unicode"


def test_astral_characters_use_code_point_indices():
    """A producer using byte or UTF-16 offsets must fail rather than record a
    wrong span."""
    text = "emoji 😀 here"
    collector = _collector(text)
    start = text.index("😀")

    _capture(collector, _m("😀", start, start + 1))

    assert collector.finalize()[0].value == "😀"


def test_a_utf16_style_offset_fails_rather_than_recording_a_wrong_span():
    text = "😀abc"
    collector = _collector(text)
    # UTF-16 would put "abc" at 2:5; code points put it at 1:4.
    with pytest.raises(EvidenceError):
        _capture(collector, _m("abc", 2, 5))


# ---------------------------------------------------------------------------
# Runtime typing and error hygiene
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs,code",
    [
        ({"kind": "nonsense", "index": 0, "field": "content"}, "source.kind.invalid"),
        ({"kind": "message", "index": 0, "field": "nonsense"}, "source.field.invalid"),
        ({"kind": "message", "index": -1, "field": "content"}, "source.index.invalid"),
        ({"kind": "message", "index": 0, "field": "content", "role": "has spaces"}, "source.role.invalid"),
    ],
)
def test_source_fields_are_validated_at_runtime(kwargs, code):
    """Literal annotations do not validate anything at runtime."""
    with pytest.raises(EvidenceError) as exc:
        SourceRef(**kwargs)
    assert exc.value.code == code


@pytest.mark.parametrize(
    "kwargs,code",
    [
        ({"detector": ""}, "match.detector.invalid"),
        ({"detector": "leaked secret hunter2"}, "match.detector.invalid"),
        ({"match_type": "not an identifier"}, "match.type.invalid"),
        ({"rule_id": "also not one"}, "match.rule_id.invalid"),
    ],
)
def test_match_identifiers_are_validated_at_runtime(kwargs, code):
    """These are interpolated into errors and stored, so a value carrying
    protected content must not get that far."""
    base = {"detector": "pii", "match_type": "EMAIL", "source": MSG, "value": "x", "start": 0, "end": 1}
    with pytest.raises(EvidenceError) as exc:
        ExactMatch(**{**base, **kwargs})
    assert exc.value.code == code


def test_no_error_path_quotes_content_offsets_or_caller_strings():
    """This runs where operator logs can see it, and the values in question are
    exactly what the product exists to protect."""
    secret = "hunter2"
    text = f"my password is {secret}"
    collector = _collector(text)

    failures = []
    for build in (
        lambda: _capture(collector, _m(secret, 0, 7)),  # stale span
        lambda: _capture(collector, _m(secret, 0, 9999)),  # out of range
        lambda: collector.register_source(MSG, "different"),  # conflicting
    ):
        with pytest.raises(EvidenceError) as exc:
            build()
        failures.append(str(exc.value))

    for message in failures:
        assert secret not in message
        assert "my password" not in message
        assert "9999" not in message


# ---------------------------------------------------------------------------
# Round 2: failure must also be terminal, and captures must not overlap
# ---------------------------------------------------------------------------


def test_a_failed_finalize_still_destroys_state_and_is_terminal():
    """Clearing only on success left a fully populated collector behind every
    failure — the caller could retry, add sources, or simply keep it."""
    value = "secret"
    text = " ".join([value] * (MAX_OCCURRENCES_PER_GROUP + 2))
    collector = _collector(text)
    with collector.capture("pii") as batch:
        pos = 0
        for _ in range(MAX_OCCURRENCES_PER_GROUP + 2):
            start = text.index(value, pos)
            batch.add(_m(value, start, start + len(value)))
            pos = start + len(value)

    with pytest.raises(EvidenceError):
        collector.finalize()

    assert collector._originals == {}
    assert collector._matches == []
    with pytest.raises(EvidenceError) as exc:
        collector.finalize()
    assert exc.value.code == "collector.finalized"


def test_the_overflow_path_does_not_leave_the_batch_in_its_own_frames():
    """My first version of this test was vacuous.

    It collected only locals that were lists, so it saw the already-emptied
    `groups` and missed `grouped`, which is a dict, and missed bare
    ExactMatch/str locals entirely. This walks every local recursively.

    Note what is being asserted: the containers this module owns are emptied on
    the way out. It is NOT a secrecy guarantee against code in the same
    process — Python tracebacks keep their frames' locals and there is no way
    to prevent that from inside a library.
    """
    collector = MatchCollector()
    value = "v" * (MAX_VALUE_BYTES - 1)
    for i in range(MAX_MATCH_GROUPS):
        src = SourceRef(kind="message", index=i, field="content", role="user")
        collector.register_source(src, value)
        _capture(collector, _m(value, 0, len(value), source=src))

    with pytest.raises(EvidenceError) as exc:
        collector.finalize()
    assert exc.value.code == "capture.serialized_too_large"

    def walk(obj, depth=0, seen=None):
        """Every container reachable from a traceback frame."""
        seen = seen if seen is not None else set()
        if depth > 6 or id(obj) in seen:
            return []
        seen.add(id(obj))
        found = []
        if isinstance(obj, MatchGroup | ExactMatch):
            found.append(obj)
            return found
        if isinstance(obj, dict):
            for k, v in obj.items():
                found += walk(k, depth + 1, seen) + walk(v, depth + 1, seen)
        elif isinstance(obj, list | tuple | set):
            for v in obj:
                found += walk(v, depth + 1, seen)
        return found

    retained = []
    tb = exc.tb
    while tb is not None:
        for local in tb.tb_frame.f_locals.values():
            retained += walk(local)
        tb = tb.tb_next

    assert not retained, f"{len(retained)} match objects still reachable through the traceback frames"


def test_a_directly_mutated_batch_cannot_smuggle_a_match_past_validation():
    """Python gives no real privacy for `_staged`, so the commit cannot assume
    the list holds only what add() put there."""
    collector = _collector("alice@example.com")

    with pytest.raises(EvidenceError) as exc:
        with collector.capture("pii") as batch:
            batch.add(_m("alice@example.com", 0, 17))
            batch._staged.append(_m("nobody@example.com", 0, 17))  # never went through add()

    assert exc.value.code == "match.span.stale"
    assert collector.finalize() == []


def test_captures_cannot_nest():
    """An inner capture could commit while the outer block rolled back."""
    collector = _collector("hello")
    with pytest.raises(EvidenceError) as exc:
        with collector.capture("pii"):
            with collector.capture("pii"):
                pass
    assert exc.value.code == "collector.capture_already_open"


def test_finalize_cannot_run_inside_a_capture():
    """It returned [], cleared state, marked the collector finalized, and then
    the clean context exit committed a match into it anyway."""
    collector = _collector("hello")
    with pytest.raises(EvidenceError) as exc:
        with collector.capture("pii") as batch:
            batch.add(_m("hello", 0, 5))
            collector.finalize()
    assert exc.value.code == "collector.capture_already_open"


def test_a_non_evidence_exception_also_discards_the_batch():
    """A caller failing mid-batch leaves exactly the same partial set as a
    validation failure."""
    collector = _collector("alice@example.com")

    with pytest.raises(RuntimeError):
        with collector.capture("pii") as batch:
            batch.add(_m("alice@example.com", 0, 17))
            raise RuntimeError("caller blew up")

    assert collector.finalize() == []


def test_a_batch_cannot_be_used_after_its_block_exits():
    """They validated, they appended, the commit had already run — so they were
    silently never stored."""
    collector = _collector("alice@example.com")
    with collector.capture("pii") as batch:
        batch.add(_m("alice@example.com", 0, 17))

    with pytest.raises(EvidenceError) as exc:
        batch.add(_m("alice@example.com", 0, 17))
    assert exc.value.code == "capture.closed"


def test_identifiers_reject_unicode_confusables():
    """str.isalnum() accepts Cyrillic and fullwidth characters, so two
    identifiers could look identical and not be."""
    for confusable in ("ріі", "１２３", "café"):
        with pytest.raises(EvidenceError) as exc:
            ExactMatch(detector=confusable, match_type="X", source=MSG, value="x", start=0, end=1)
        assert exc.value.code == "match.detector.invalid"


def test_the_stored_form_carries_a_schema_version():
    """Step 4 must store these bytes rather than re-serialise the dicts."""
    import json

    collector = _collector("alice@example.com")
    _capture(collector, _m("alice@example.com", 0, 17))

    payload = json.loads(canonical_json(collector.finalize()))

    assert payload["schema_version"] == 1
    assert payload["matches"][0]["value"] == "alice@example.com"
    assert "start" not in json_keys(payload)
