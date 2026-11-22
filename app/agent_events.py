"""Strict metadata-only wire types for the collector v1 contract."""

import hashlib
import json
from datetime import datetime
from typing import Annotated, Any, Literal, Self, get_args

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator, model_validator

MAX_BATCH_BYTES = 65_536
MAX_HEARTBEAT_BYTES = 2_048
MAX_OBSERVATION_BYTES = 4_096
MAX_JSON_DEPTH = 12
MAX_WIRE_INTEGER = 9_007_199_254_740_991

_Version = Annotated[int, Field(ge=1, le=1)]
_PositiveCount = Annotated[int, Field(ge=1, le=MAX_WIRE_INTEGER)]
_Count = Annotated[int, Field(ge=0, le=MAX_WIRE_INTEGER)]
_HexToken = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", max_length=64)]
_UUID4 = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", max_length=36),
]
_AdapterVersion = Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$", max_length=24)]
_SourceTime = Annotated[
    str,
    StringConstraints(
        pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$",
        max_length=27,
    ),
]
_UpstreamSHA = Literal["7ec2891b0904dad621bb13f24312121d05d4ca03"]
_Kind = Literal["session.start", "prompt", "file.read", "network", "tool.call", "tool.result", "sensor"]
_HookEvent = Literal["UserPromptSubmit", "PreToolUse", "PostToolUse"]

Availability = Literal[
    "metadata_only", "capture_disabled", "redacted", "truncated", "unsupported", "source_unavailable"
]
Gap = Literal[
    "malformed_record",
    "content_truncated",
    "missing_tool_call",
    "missing_native_session_id",
    "missing_native_tool_call_id",
    "unsupported_content",
    "skipped_content",
    "other_parser_gap",
]
WireCode = Literal["unsupported_version", "invalid_envelope", "invalid_row"]

_TRANSCRIPT_KINDS = frozenset({"session.start", "prompt", "file.read", "network", "tool.result", "sensor"})
_HOOK_KINDS = {"UserPromptSubmit": "prompt", "PreToolUse": "tool.call", "PostToolUse": "tool.result"}


class _WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class Transcript(_WireModel):
    channel: Literal["transcript"]
    parser_observation_token: _HexToken
    parser_logical_token: _HexToken
    parser_evidence_version: _Version
    stream_token: _HexToken
    byte_position: _PositiveCount
    part: Annotated[int, Field(ge=0, le=65_535)]
    record_token: _HexToken
    record_origin: Literal["native", "parser_generated"]


class Hook(_WireModel):
    channel: Literal["hook"]
    collector_observation_id: _UUID4
    native_event: _HookEvent


class Observation(_WireModel):
    source: Annotated[Transcript | Hook, Field(discriminator="channel")]
    agent: Literal["claude-code"]
    fixture_profile: Literal["claude-fixture-v1"]
    upstream_sha: _UpstreamSHA
    adapter_version: _AdapterVersion
    kind: _Kind
    native_session_token: _HexToken | None = None
    native_tool_call_token: _HexToken | None = None
    tool_name: Literal["Read", "WebFetch"] | None = None
    source_at: _SourceTime | None = None
    availability: Availability
    gaps: Annotated[list[Gap], Field(max_length=8)]

    @field_validator("native_session_token", "native_tool_call_token", "tool_name", "source_at")
    @classmethod
    def _omit_optional_values(cls, value: str | None) -> str:
        # An omitted field uses its default, so only explicit nulls reach here.
        if value is None:
            raise ValueError("omit an absent field")
        return value

    @field_validator("source_at")
    @classmethod
    def _valid_source_time(cls, value: str) -> str:
        datetime.fromisoformat(value)
        return value

    @model_validator(mode="after")
    def _source_semantics(self) -> Self:
        if self.gaps != sorted(set(self.gaps)):
            raise ValueError("gap codes must be unique and sorted")
        if "content_truncated" in self.gaps and self.availability != "truncated":
            raise ValueError("truncation gap requires truncated availability")

        if isinstance(self.source, Transcript):
            if self.kind not in _TRANSCRIPT_KINDS:
                raise ValueError("invalid transcript kind")
            if self.kind in {"session.start", "sensor"} and self.source.record_origin != "parser_generated":
                raise ValueError("parser-generated transcript kind requires parser provenance")
        else:
            if _HOOK_KINDS[self.source.native_event] != self.kind:
                raise ValueError("invalid hook event and kind")
            if ("missing_native_session_id" in self.gaps) != (self.native_session_token is None):
                raise ValueError("hook session token and gap must agree")
            missing_tool = self.kind != "prompt" and self.native_tool_call_token is None
            if ("missing_native_tool_call_id" in self.gaps) != missing_tool:
                raise ValueError("hook tool call token and gap must agree")
        return self

    @property
    def source_key(self) -> str:
        if isinstance(self.source, Transcript):
            return self.source.parser_observation_token
        return self.source.collector_observation_id


class Row(_WireModel):
    ordinal: _PositiveCount
    observation: Observation


class Batch(_WireModel):
    version: _Version
    enrollment_id: _UUID4
    batch_id: _UUID4
    rows: Annotated[list[Row], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def _unique_ordered_rows(self) -> Self:
        previous = 0
        sources = set()
        for row in self.rows:
            if row.ordinal <= previous:
                raise ValueError("ordinals must strictly increase")
            previous = row.ordinal

            observation = row.observation
            key = (observation.agent, observation.source.channel, observation.source_key)
            if key in sources:
                raise ValueError("source keys must be unique")
            sources.add(key)
        return self


class Stored(_WireModel):
    ordinal: _PositiveCount
    digest: _HexToken
    outcome: Literal["accepted", "duplicate"]
    event_id: _UUID4


class Rejected(_WireModel):
    ordinal: _PositiveCount
    digest: _HexToken
    outcome: Literal["rejected"]
    reason: Literal["identity_conflict", "retired_ordinal"]


class Receipt(_WireModel):
    version: _Version
    enrollment_id: _UUID4
    batch_id: _UUID4
    results: Annotated[list[Stored | Rejected], Field(min_length=1, max_length=32)]


class LossTotals(_WireModel):
    capacity_rejected: _Count
    oversized_input: _Count
    invalid_json: _Count
    invalid_shape: _Count
    incomplete_tail: _Count
    unsupported_record: _Count
    expired: _Count
    server_conflict: _Count
    retired_ordinal: _Count
    row_schema_invalid: _Count


class Heartbeat(_WireModel):
    version: _Version
    enrollment_id: _UUID4
    revision: _PositiveCount
    upstream_sha: _UpstreamSHA
    adapter_version: _AdapterVersion
    pending: _Count
    queue_bytes: _Count
    totals: LossTotals
    state: Literal["ready", "blocked_storage", "quarantined", "source_incomplete", "contract_mismatch"]


class HeartbeatAck(_WireModel):
    version: _Version
    enrollment_id: _UUID4
    revision: _PositiveCount
    capture: Literal["metadata_only"]
    retain_content: bool

    @field_validator("retain_content")
    @classmethod
    def _retention_disabled(cls, value: bool) -> bool:
        if value:
            raise ValueError("content retention must be disabled")
        return value


class WireRefusal(_WireModel):
    code: WireCode


class WireError(ValueError):
    """Sanitized request refusal that is safe to return as a WireRefusal."""

    def __init__(self, code: str) -> None:
        if code not in get_args(WireCode):
            raise ValueError("unknown wire refusal code")
        self.refusal = WireRefusal.model_validate({"code": code})
        self.code = self.refusal.code
        super().__init__(self.code)


def _check_json_depth(text: str) -> None:
    # Count containers before calling the recursive decoder. Quoted punctuation
    # (including after an escaped quote) is data.
    depth = 0
    quoted = False
    escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "{[":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON depth limit")
        elif character in "}]":
            depth -= 1
            if depth < 0:
                raise ValueError("unmatched JSON delimiter")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> None:
    raise ValueError("nonfinite JSON number")


def _decode_envelope(data: bytes, limit: int) -> dict[str, Any]:
    if len(data) > limit:
        raise WireError("invalid_envelope")
    try:
        text = data.decode("utf-8")
        _check_json_depth(text)
        value = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_nonfinite)
    except ValueError:
        # Raise outside the handler to avoid chaining input-bearing exceptions.
        pass
    else:
        if isinstance(value, dict) and type(value.get("version")) is int:
            if value["version"] != 1:
                raise WireError("unsupported_version")
            return value
    raise WireError("invalid_envelope")


def canonical_observation_bytes(value: Observation) -> bytes:
    """Canonical metadata only, preserving omitted fields and source-time text."""
    return json.dumps(
        value.model_dump(mode="json", exclude_unset=True),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def check_observation_size(canonical: bytes) -> None:
    if len(canonical) > MAX_OBSERVATION_BYTES:
        raise WireError("invalid_row")


def observation_digest(value: Observation) -> str:
    return hashlib.sha256(canonical_observation_bytes(value)).hexdigest()


def parse_batch(data: bytes) -> Batch:
    envelope = _decode_envelope(data, MAX_BATCH_BYTES)
    try:
        batch = Batch.model_validate(envelope)
    except ValidationError as error:
        # A batch with invalid framing/ordinals/row wrappers cannot be repaired
        # by handling a bad observation locally. Classify the envelope first.
        code = "invalid_row"
        for issue in error.errors(include_input=False, include_context=False, include_url=False):
            location = issue["loc"]
            if len(location) < 3 or location[0] != "rows" or location[2] != "observation":
                code = "invalid_envelope"
                break
    else:
        for row in batch.rows:
            check_observation_size(canonical_observation_bytes(row.observation))
        return batch
    raise WireError(code)


def parse_heartbeat(data: bytes) -> Heartbeat:
    envelope = _decode_envelope(data, MAX_HEARTBEAT_BYTES)
    try:
        return Heartbeat.model_validate(envelope)
    except ValidationError:
        pass
    raise WireError("invalid_envelope")
