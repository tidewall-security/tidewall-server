"""Projecting stored content into what a caller may see.

One place, because the read endpoint and content export must return exactly the
same thing for the same row and view. When this lived privately inside the route
module, a second caller would have duplicated the field selection and the two
would have drifted.

Nothing here touches HTTP. It takes already-scoped raw column values -- the
caller has proved the row is theirs -- and returns a validated projection or
raises.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

#: SQLAlchemy's SQLite DateTime bind processor writes exactly this, for both
#: aware and naive inputs: 26 characters, zero-padded, naive UTC. Fixed width is
#: what makes SQLite's lexicographic comparison chronological, which is what the
#: expiry CASE in the read query relies on. A value in any other shape did not
#: come from this application.
_STORED_TIMESTAMP = "%Y-%m-%d %H:%M:%S.%f"


class Corrupt(Exception):
    """Stored content is not what this system writes. Server-side corruption."""


# ---------------------------------------------------------------------------
# Parsing and validation
# ---------------------------------------------------------------------------


def parse_stored_timestamp(raw: object) -> datetime:
    """Parse a stored timestamp, accepting only the canonical form.

    Only the exact form SQLAlchemy's SQLite DateTime writes. A parseable but
    non-canonical value -- one carrying a UTC offset, say -- can sort
    differently from its chronological position, so the query's expiry CASE and
    this parse could disagree and produce a 200 full of nulls for a row that is
    not actually expired. Restricting to the written form makes them provably
    equivalent, and anything else did not come from here.
    """
    if not isinstance(raw, str):
        raise Corrupt("timestamp is not text")
    try:
        return datetime.strptime(raw, _STORED_TIMESTAMP).replace(tzinfo=UTC)
    except ValueError as exc:
        raise Corrupt("timestamp is not in the stored form") from exc


def render_timestamp(moment: datetime) -> str:
    """One rendering, because "ISO-8601 UTC" does not determine a unique body.

    Z rather than +00:00, and isoformat's own fractional-second behaviour rather
    than a hand-rolled format string.
    """
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def decode_json_column(raw: object, field: str) -> Any:
    """Decode a payload column that the query handed back as text.

    The columns are cast to TEXT in SQL precisely so nothing is parsed while the
    row is being fetched: SQLAlchemy's JSON result processor would raise there,
    before this endpoint could classify the row or write its denied_corrupt
    audit. Decoding here puts the failure inside the boundary that can.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise Corrupt(f"{field} is not text")
    try:
        # Python's json accepts NaN and Infinity, which are not JSON. Under an
        # application/json contract, emitting a non-standard token or silently
        # coercing it are both worse than refusing.
        return json.loads(raw, parse_constant=_reject_constant)
    except (ValueError, Corrupt) as exc:
        raise Corrupt(f"{field} is not valid JSON") from exc


def _reject_constant(name: str) -> Any:
    raise Corrupt(f"non-finite number {name}")


def _strict_int(value: object, *, minimum: int) -> int:
    """An integer, not a bool. ``bool`` is an ``int`` in Python, and Pydantic
    coerces by default, so ``{"occurrences": "1"}`` had two defensible answers."""
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise Corrupt("expected an integer")
    return value


def _strict_str(value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise Corrupt("expected a string")
    return value


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return _strict_str(value, allow_empty=True)


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------
#
# Built field by field. Every field is always present and null carries the
# meaning, so there is no absent-versus-null rule to get wrong -- and SQL NULL
# and JSON null are deliberately not distinguished, because the difference is
# only how the row happened to be written.


_MATCH_KEYS = {"detector", "match_type", "rule_id", "source", "value", "occurrences"}
_SOURCE_KEYS = {"kind", "index", "field", "role"}


def _match_group(raw: object) -> dict[str, Any]:
    """One stored match. Exact keys required.

    Unlike the caller's messages, this system wrote these itself, so an
    unexpected shape is tampering or version skew rather than a permissive
    caller.
    """
    if not isinstance(raw, dict) or set(raw) != _MATCH_KEYS:
        raise Corrupt("match group has unexpected keys")
    source = raw["source"]
    if not isinstance(source, dict) or set(source) != _SOURCE_KEYS:
        raise Corrupt("match source has unexpected keys")
    return {
        "detector": _strict_str(raw["detector"]),
        "match_type": _strict_str(raw["match_type"]),
        "rule_id": _optional_str(raw["rule_id"]),
        "source": {
            # Any non-empty string, deliberately. These vocabularies can grow
            # inside schema version 1, they drive no authorization, parsing or
            # control flow, and rejecting evidence over a vocabulary addition
            # would destroy readable forensic data to no purpose.
            "kind": _strict_str(source["kind"]),
            "index": _strict_int(source["index"], minimum=0),
            "field": _strict_str(source["field"]),
            "role": _optional_str(source["role"]),
        },
        "value": _strict_str(raw["value"], allow_empty=True),
        "occurrences": _strict_int(raw["occurrences"], minimum=1),
    }


def project_matches_block(raw: object) -> dict[str, Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "matches"}:
        raise Corrupt("matches has unexpected keys")
    version = raw["schema_version"]
    # Exactly the JSON integer 1. Not true, not 1.0, not "1". A future writer
    # that bumps the version must land with a reader that understands it;
    # rendering a version this code does not know would be guessing at the
    # meaning of forensic evidence.
    if isinstance(version, bool) or version != 1 or not isinstance(version, int):
        raise Corrupt("unsupported matches schema version")
    groups = raw["matches"]
    if not isinstance(groups, list):
        raise Corrupt("matches is not a list")
    return {"schema_version": 1, "matches": [_match_group(g) for g in groups]}


def _list_or_none(raw: object, field: str) -> list[Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise Corrupt(f"{field} is not a list")
    return raw


def _split_input(raw: object) -> tuple[list[Any] | None, list[Any] | None]:
    """Messages and tools out of the stored input.

    build_content() writes the wrapper whenever tools were supplied at all,
    including an empty list, and the bare message list otherwise. There is no
    tools column to read instead.
    """
    if raw is None:
        return None, None
    if isinstance(raw, list):
        return raw, None
    if isinstance(raw, dict):
        if set(raw) != {"messages", "tools"}:
            raise Corrupt("input wrapper has unexpected keys")
        return _list_or_none(raw["messages"], "messages"), _list_or_none(raw["tools"], "tools")
    raise Corrupt("input is neither a message list nor the wrapper")


def project_content(
    *,
    view: str,
    captured_raw: object,
    expires_raw: object,
    input_raw: object,
    output_raw: object,
    matches_raw: object,
) -> dict[str, Any]:
    """The view-specific body, shared by the read endpoint and content export.

    Returns the fields for that view only -- the caller supplies its own
    envelope, because the read endpoint and export wrap this differently. Raises
    :class:`Corrupt` for anything the server would not have written.
    """
    expires_at = None if expires_raw is None else parse_stored_timestamp(expires_raw)
    out: dict[str, Any] = {
        "captured_at": render_timestamp(parse_stored_timestamp(captured_raw)),
        "expires_at": None if expires_at is None else render_timestamp(expires_at),
    }
    if view == "full":
        # Only the full view decodes input and output. Corruption in a column
        # this view does not serve cannot fail a matches projection, and a
        # caller without the full grant should not have the prompt decoded on
        # their behalf.
        messages, tools = _split_input(decode_json_column(input_raw, "input"))
        out["messages"] = messages
        out["tools"] = tools
        out["output"] = _list_or_none(decode_json_column(output_raw, "output"), "output")
    out["matches"] = project_matches_block(decode_json_column(matches_raw, "matches"))
    return out


def canonical_json(body: dict[str, Any]) -> str:
    """One encoder, so two callers cannot produce different bytes.

    Fixed separators because a non-enumerability test compares body bytes;
    ensure_ascii=False because the transport is UTF-8 and escaping captured
    non-ASCII would be gratuitous; allow_nan=False because Python's json accepts
    NaN and Infinity, which are not JSON.
    """
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
