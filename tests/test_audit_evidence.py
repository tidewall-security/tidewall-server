"""The internal exact-match channel (P0-6, step 1).

These matter more than most unit tests: this is the mechanism that decides
what exact content gets stored under the middle role tier. If a match can be
recorded without being verified against the text it claims to come from, then
whatever ends up in the audit record is unprovenanced — and it is exactly the
content the product exists to protect.
"""

from __future__ import annotations

import pytest

from app.services.audit_evidence import (
    MAX_MATCH_GROUPS,
    MAX_OCCURRENCES_PER_GROUP,
    MAX_VALUE_BYTES,
    EvidenceError,
    ExactMatch,
    MatchCollector,
    SourceRef,
)

MSG = SourceRef(kind="message", index=0, field="content", role="user")


def _collector(text: str, source: SourceRef = MSG) -> MatchCollector:
    c = MatchCollector()
    c.register_source(source, text)
    return c


def _match(value: str, start: int, end: int, **kw) -> ExactMatch:
    return ExactMatch(
        detector=kw.pop("detector", "pii"),
        match_type=kw.pop("match_type", "EMAIL_ADDRESS"),
        source=kw.pop("source", MSG),
        value=value,
        start=start,
        end=end,
        **kw,
    )


def test_a_match_that_does_not_match_is_refused():
    """The whole point of the channel.

    A detector reporting a value that is not at the offsets it reported has
    read something else — a transformed copy, a stale buffer, a different
    message. Recording it would attach provenance to content that never had it.
    """
    text = "contact alice@example.com please"
    collector = _collector(text)

    with pytest.raises(EvidenceError, match="no longer contains"):
        collector.add(_match("bob@example.com", 8, 25))


def test_a_correct_match_is_accepted_and_grouped():
    text = "contact alice@example.com please"
    collector = _collector(text)

    collector.add(_match("alice@example.com", 8, 25))

    groups = collector.grouped()
    assert len(groups) == 1
    assert groups[0].value == "alice@example.com"
    assert groups[0].occurrences == 1


def test_offsets_do_not_survive_grouping():
    """Offsets are a validation aid, not a record.

    A start/end pair against a known field is a reconstruction aid for anyone
    who later obtains a fragment of the original, so it must not reach storage.
    """
    text = "alice@example.com"
    collector = _collector(text)
    collector.add(_match("alice@example.com", 0, 17))

    group = collector.grouped()[0]

    assert not hasattr(group, "start")
    assert not hasattr(group, "end")
    assert "start" not in vars(group)
    assert "end" not in vars(group)


def test_a_span_outside_the_field_is_refused():
    collector = _collector("short")
    with pytest.raises(EvidenceError, match="outside the"):
        collector.add(_match("short", 0, 500))


def test_an_unregistered_source_is_refused():
    """A detector cannot invent provenance for a field the scanner never read."""
    collector = _collector("hello")
    other = SourceRef(kind="tool", index=3, field="description")

    with pytest.raises(EvidenceError, match="never registered"):
        collector.add(_match("hello", 0, 5, source=other))


def test_non_canonical_unicode_is_refused():
    """Otherwise one value stores under several representations and grouping,
    comparison and deduplication all quietly stop working."""
    decomposed = "café"  # e + combining acute, not the composed form
    collector = _collector(f"visit {decomposed} now")

    with pytest.raises(EvidenceError, match="canonical"):
        collector.add(_match(decomposed, 6, 6 + len(decomposed)))


def test_an_oversized_value_is_refused():
    big = "a" * (MAX_VALUE_BYTES + 1)
    collector = _collector(big)
    with pytest.raises(EvidenceError, match="exceeds"):
        collector.add(_match(big, 0, len(big)))


def test_the_same_value_in_different_messages_stays_separate():
    """Provenance is identity.

    The same address in a user's question and in a tool's response are
    different findings, and merging them would erase which one leaked.
    """
    first = SourceRef(kind="message", index=0, field="content", role="user")
    second = SourceRef(kind="message", index=1, field="content", role="assistant")
    collector = MatchCollector()
    collector.register_source(first, "alice@example.com")
    collector.register_source(second, "alice@example.com")

    collector.add(_match("alice@example.com", 0, 17, source=first))
    collector.add(_match("alice@example.com", 0, 17, source=second))

    assert len(collector.grouped()) == 2


def test_the_same_value_twice_in_one_field_is_counted_not_duplicated():
    text = "alice@example.com and alice@example.com"
    collector = _collector(text)

    collector.add(_match("alice@example.com", 0, 17))
    collector.add(_match("alice@example.com", 22, 39))

    groups = collector.grouped()
    assert len(groups) == 1
    assert groups[0].occurrences == 2


def test_overlapping_matches_from_different_detectors_stay_separate():
    """Collapsing them would discard why each detector fired, which is the
    thing an analyst is reading the record to find out."""
    text = "key=AKIAIOSFODNN7EXAMPLE"
    collector = _collector(text)

    collector.add(_match("AKIAIOSFODNN7EXAMPLE", 4, 24, detector="secrets", match_type="AWS_KEY"))
    collector.add(_match("AKIAIOSFODNN7EXAMPLE", 4, 24, detector="custom_entity", match_type="CUSTOM", rule_id="r1"))

    assert len(collector.grouped()) == 2


def test_too_many_distinct_matches_fails_rather_than_truncating():
    """A truncated set reads as a complete one to whoever inspects it later,
    and nothing in the record says it was cut."""
    text = " ".join(f"value{i:04d}" for i in range(MAX_MATCH_GROUPS + 5))
    collector = _collector(text)
    for i in range(MAX_MATCH_GROUPS + 5):
        value = f"value{i:04d}"
        start = text.index(value)
        collector.add(_match(value, start, start + len(value)))

    with pytest.raises(EvidenceError, match="refusing to record a partial set"):
        collector.grouped()


def test_too_many_occurrences_fails_rather_than_undercounting():
    value = "secret"
    text = " ".join([value] * (MAX_OCCURRENCES_PER_GROUP + 2))
    collector = _collector(text)
    pos = 0
    for _ in range(MAX_OCCURRENCES_PER_GROUP + 2):
        start = text.index(value, pos)
        collector.add(_match(value, start, start + len(value)))
        pos = start + len(value)

    with pytest.raises(EvidenceError, match="refusing to record a partial count"):
        collector.grouped()


def test_ordering_is_deterministic():
    """Two audit records over the same input must not differ for no reason."""
    text = "bbb aaa ccc"
    positions = {"aaa": 4, "bbb": 0, "ccc": 8}

    def build(order):
        c = _collector(text)
        for v in order:
            c.add(_match(v, positions[v], positions[v] + 3))
        return [(g.value, g.occurrences) for g in c.grouped()]

    assert build(["aaa", "bbb", "ccc"]) == build(["ccc", "aaa", "bbb"])


def test_a_negative_source_index_is_refused():
    with pytest.raises(EvidenceError, match="negative"):
        SourceRef(kind="message", index=-1, field="content")


def test_the_error_does_not_quote_the_content_it_is_protecting():
    """This runs on a path that can reach an operator's log, and the mismatch
    is between two pieces of exactly the content being protected."""
    collector = _collector("my password is hunter2")

    with pytest.raises(EvidenceError) as exc:
        collector.add(_match("hunter2", 0, 7))

    assert "hunter2" not in str(exc.value)
    assert "my password" not in str(exc.value)
