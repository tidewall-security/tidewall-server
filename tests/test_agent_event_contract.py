import json
from pathlib import Path

import pytest

from app import agent_events as wire

VECTORS = json.loads((Path(__file__).parent / "fixtures/collector_v1.json").read_text())
OBSERVATIONS = {entry["name"]: entry["canonical"] for entry in VECTORS["observation_vectors"]}
HOOK = "hook_orphan_result"
TRANSCRIPT = "transcript_file_read_A"
MAX_INTEGER = 9_007_199_254_740_991
SENTINEL = "sensitive_fixture_sentinel"


def body(value):
    return json.dumps(value).encode()


def batch_with(name=HOOK):
    batch = json.loads(VECTORS["batch"])
    observation = json.loads(OBSERVATIONS[name])
    batch["rows"][0]["observation"] = observation
    return batch, observation


def assert_refused(data, code, *, parser="parse_batch"):
    with pytest.raises(wire.WireError) as raised:
        getattr(wire, parser)(data)
    error = raised.value
    assert error.code == code
    refusal_body = error.refusal.model_dump_json().encode()
    assert refusal_body == VECTORS["responses"]["refusals"][code].encode()
    assert len(refusal_body) <= 128
    return error


@pytest.mark.parametrize("vector", VECTORS["observation_vectors"], ids=lambda vector: vector["name"])
def test_wire_vectors(vector):
    batch, observation = batch_with(vector["name"])
    # json.dumps inserts spaces and the wrapper carries IDs outside the digest.
    parsed = wire.parse_batch(body(batch))
    value = parsed.rows[0].observation
    assert wire.canonical_observation_bytes(value) == vector["canonical"].encode("ascii")
    assert wire.observation_digest(value) == vector["sha256"]
    assert value.model_dump(exclude_unset=True) == observation

    if observation["source"]["channel"] == "transcript":
        assert isinstance(value.source, wire.Transcript)
        assert value.source.parser_evidence_version == 1
        assert len(value.source.parser_observation_token) == len(value.source.parser_logical_token) == 64
    else:
        assert isinstance(value.source, wire.Hook)
        assert value.source.collector_observation_id == "12345678-abcd-4000-8000-000000000003"

    if vector["name"] == "largest_v1_observation":
        assert vector["canonical_size"] == 1137 == len(wire.canonical_observation_bytes(value))
        assert value.source_at == "2024-02-29T23:59:59.120000Z"


@pytest.mark.parametrize("vector", VECTORS["negative_requests"], ids=lambda vector: vector["name"])
def test_refusal_vectors(vector):
    assert_refused(vector["body"].encode(), vector["code"], parser=f"parse_{vector['request']}")


def test_response_vectors():
    responses = VECTORS["responses"]
    for name, result_type in [
        ("receipt", wire.Stored),
        ("duplicate_receipt", wire.Stored),
        ("rejected_receipt", wire.Rejected),
    ]:
        receipt = wire.Receipt.model_validate_json(responses[name])
        assert isinstance(receipt.results[0], result_type)
        assert receipt.model_dump() == json.loads(responses[name])

    ack = wire.HeartbeatAck.model_validate_json(responses["heartbeat_ack"])
    assert ack.model_dump() == json.loads(responses["heartbeat_ack"])


def test_bounds_and_combinations():
    batch, _ = batch_with()
    original = batch["rows"][0]
    # Deliberately leave holes: local loss can consume transport ordinals.
    batch["rows"] = [
        {
            "ordinal": index * 2,
            "observation": {
                **original["observation"],
                "source": original["observation"]["source"]
                | {"collector_observation_id": f"12345678-abcd-4000-8000-{index:012x}"},
            },
        }
        for index in range(1, 34)
    ]
    assert_refused(body(batch), "invalid_envelope")
    batch["rows"].pop()
    encoded = body(batch)
    limit = 65_536
    assert len(wire.parse_batch(encoded.ljust(limit)).rows) == 32
    assert_refused(encoded.ljust(limit + 1), "invalid_envelope")

    wire.check_observation_size(b" " * 4_096)
    with pytest.raises(wire.WireError, match="^invalid_row$"):
        wire.check_observation_size(b" " * 4_097)


@pytest.mark.parametrize(
    ("native_event", "kind"),
    [("UserPromptSubmit", "prompt"), ("PreToolUse", "tool.call"), ("PostToolUse", "tool.result")],
)
def test_hook_combinations(native_event, kind):
    batch, observation = batch_with()
    observation.update(kind=kind, gaps=[], native_session_token="a" * 64)
    observation["source"]["native_event"] = native_event
    if native_event != "UserPromptSubmit":
        observation["native_tool_call_token"] = "b" * 64
    else:
        observation.pop("tool_name")
    assert wire.parse_batch(body(batch)).rows[0].observation.kind == kind

    observation["kind"] = "tool.call" if kind == "prompt" else "prompt"
    assert_refused(body(batch), "invalid_row")


@pytest.mark.parametrize("kind", ["session.start", "prompt", "file.read", "network", "tool.result", "sensor"])
def test_transcript_combinations(kind):
    batch, observation = batch_with(TRANSCRIPT)
    observation["kind"] = kind
    if kind in {"session.start", "sensor"}:
        observation["source"]["record_origin"] = "parser_generated"
    assert wire.parse_batch(body(batch)).rows[0].observation.kind == kind

    observation["kind"] = "tool.call"
    assert_refused(body(batch), "invalid_row")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent", "another-agent"),
        ("fixture_profile", "claude-fixture-v2"),
        ("upstream_sha", "0" * 40),
        ("adapter_version", "1.0.0-alpha"),
        ("adapter_version", "123456789.1234567.1234567"),
        ("kind", "summary"),
        ("availability", "assessed"),
        ("gaps", ["other_parser_gap", "malformed_record"]),
        ("gaps", ["other_parser_gap", "other_parser_gap"]),
        ("gaps", ["unknown"]),
        ("gaps", ["content_truncated"]),
        ("gaps", None),
        ("source_at", None),
        ("native_session_token", None),
        ("native_tool_call_token", None),
        ("tool_name", None),
        ("source_at", "2025-02-29T12:00:00Z"),
        ("source_at", "2024-02-29T12:00:60Z"),
        ("source_at", "2024-02-29T24:00:00Z"),
        ("source_at", "2024-02-29T12:00:00+00:00"),
        ("source_at", "2024-02-29T12:00:00.0123456Z"),
        ("source_at", "２０２４-02-29T12:00:00Z"),
        ("native_session_token", "A" * 64),
        ("native_tool_call_token", "a" * 63),
        ("tool_name", "Bash"),
        ("policy_id", SENTINEL),
        ("content", SENTINEL),
        ("score", 1),
        ("metadata", {}),
    ],
)
def test_invalid_observation(field, value):
    batch, observation = batch_with(TRANSCRIPT)
    observation[field] = value
    assert_refused(body(batch), "invalid_row")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("parser_evidence_version", True),
        ("parser_evidence_version", 1.0),
        ("parser_evidence_version", 2),
        ("byte_position", 0),
        ("byte_position", MAX_INTEGER + 1),
        ("byte_position", "329"),
        ("part", -1),
        ("part", 65_536),
        ("part", 1.0),
        ("record_origin", "unknown"),
        ("stream_token", "x" * 64),
        ("collector_observation_id", "12345678-abcd-4000-8000-000000000003"),
    ],
)
def test_invalid_parser_evidence(field, value):
    batch, observation = batch_with(TRANSCRIPT)
    observation["source"][field] = value
    assert_refused(body(batch), "invalid_row")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("collector_observation_id", "12345678-ABCD-4000-8000-000000000003"),
        ("collector_observation_id", "12345678-abcd-5000-8000-000000000003"),
        ("collector_observation_id", "12345678-abcd-4000-7000-000000000003"),
        ("collector_observation_id", "12345678-abcd-4000-8000-000000000003\n"),
        ("native_event", "SessionStart"),
        ("parser_evidence_version", 1),
    ],
)
def test_invalid_hook_evidence(field, value):
    batch, observation = batch_with()
    observation["source"][field] = value
    assert_refused(body(batch), "invalid_row")


@pytest.mark.parametrize("field", ["parser_observation_token", "parser_logical_token", "byte_position", "record_token"])
def test_transcript_requires_parser_evidence(field):
    batch, observation = batch_with(TRANSCRIPT)
    del observation["source"][field]
    assert_refused(body(batch), "invalid_row")


def test_hook_requires_collector_uuid():
    batch, observation = batch_with()
    del observation["source"]["collector_observation_id"]
    assert_refused(body(batch), "invalid_row")


@pytest.mark.parametrize("field", ["native_session_token", "native_tool_call_token"])
def test_hook_rejects_tokens_with_corresponding_missing_gap(field):
    batch, observation = batch_with()
    observation[field] = "a" * 64
    assert_refused(body(batch), "invalid_row")


@pytest.mark.parametrize("present", [True, False])
def test_gap_for_prompt_tool_id_is_inapplicable(present):
    batch, observation = batch_with()
    observation.update(kind="prompt", gaps=["missing_native_session_id", "missing_native_tool_call_id"])
    observation["source"]["native_event"] = "UserPromptSubmit"
    observation.pop("tool_name")
    if present:
        observation["native_tool_call_token"] = "b" * 64
    assert_refused(body(batch), "invalid_row")


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"version": 2}, "unsupported_version"),
        ({"version": True}, "invalid_envelope"),
        ({"version": 1.0}, "invalid_envelope"),
        ({"version": "1"}, "invalid_envelope"),
        ({"version": None}, "invalid_envelope"),
        ({"enrollment_id": None}, "invalid_envelope"),
        ({"policy_id": SENTINEL}, "invalid_envelope"),
        ({"rows": []}, "invalid_envelope"),
        ({"rows": {}}, "invalid_envelope"),
    ],
)
def test_invalid_batch_envelope(change, code):
    batch, _ = batch_with()
    assert_refused(body(batch | change), code)


@pytest.mark.parametrize("ordinal", [0, True, "41", 41.0, MAX_INTEGER + 1])
def test_ordinals_are_bounded_integers(ordinal):
    batch, _ = batch_with()
    batch["rows"][0]["ordinal"] = ordinal
    assert_refused(body(batch), "invalid_envelope")


@pytest.mark.parametrize("ordinal", [40, 41])
def test_batch_rejects_decreasing_or_duplicate_ordinals(ordinal):
    batch, _ = batch_with()
    _, other_channel = batch_with(TRANSCRIPT)
    batch["rows"].append({"ordinal": ordinal, "observation": other_channel})
    assert_refused(body(batch), "invalid_envelope")


@pytest.mark.parametrize("name", [HOOK, TRANSCRIPT])
def test_batch_rejects_duplicate_source_key(name):
    batch, observation = batch_with(name)
    # A changed digest does not change the source identity.
    batch["rows"].append({"ordinal": 42, "observation": observation | {"availability": "redacted"}})
    assert_refused(body(batch), "invalid_envelope")


@pytest.mark.parametrize(
    "suffix",
    [b"{}", b"\xff", b"\x00", b"\\n", b"\xef\xbb\xbf"],
)
def test_batch_rejects_trailing_values_or_bad_encoding(suffix):
    assert_refused(VECTORS["batch"].encode() + suffix, "invalid_envelope")


def test_batch_rejects_transcoded_json():
    assert_refused(VECTORS["batch"].encode("utf-16"), "invalid_envelope")


def test_duplicate_nested_key_is_invalid_framing():
    raw = VECTORS["batch"].encode()
    raw = raw.replace(b'"channel":"hook"', b'"channel":"hook","chann\\u0065l":"hook"')
    assert_refused(raw, "invalid_envelope")


@pytest.mark.parametrize("number", [b"NaN", b"Infinity", b"-Infinity"])
def test_nonfinite_number_is_invalid_framing(number):
    raw = VECTORS["batch"].encode().replace(b'"ordinal":41', b'"ordinal":' + number)
    assert_refused(raw, "invalid_envelope")


def test_exponent_syntax_is_not_an_integer():
    raw = VECTORS["batch"].encode().replace(b'"ordinal":41', b'"ordinal":41e0')
    assert_refused(raw, "invalid_envelope")


def test_depth_limit_precedes_recursive_row_validation():
    batch, observation = batch_with()
    # The observation object is level 4. Eight arrays stay within framing
    # and reach row schema validation. The ninth exceeds the framing budget.
    depth_eight = "[" * 8 + "0" + "]" * 8
    depth_nine = "[" * 9 + "0" + "]" * 9
    observation["gaps"] = SENTINEL
    raw = body(batch)
    assert_refused(raw.replace(body(SENTINEL), depth_eight.encode()), "invalid_row")
    assert_refused(raw.replace(body(SENTINEL), depth_nine.encode()), "invalid_envelope")

    observation["gaps"] = ["{" * 14 + '"\\[']
    assert_refused(body(batch), "invalid_row")


def test_heartbeat_uses_bounded_closed_metadata():
    raw = VECTORS["heartbeat"].encode()
    assert wire.parse_heartbeat(raw.ljust(2_048)).model_dump() == json.loads(raw)
    assert_refused(raw.ljust(2_049), "invalid_envelope", parser="parse_heartbeat")
    heartbeat = json.loads(raw)
    heartbeat["totals"]["oversized_input"] = MAX_INTEGER
    assert wire.parse_heartbeat(body(heartbeat)).totals.oversized_input == MAX_INTEGER


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("version", 2, "unsupported_version"),
        ("version", True, "invalid_envelope"),
        ("revision", 0, "invalid_envelope"),
        ("pending", True, "invalid_envelope"),
        ("pending", -1, "invalid_envelope"),
        ("queue_bytes", 0.0, "invalid_envelope"),
        ("queue_bytes", MAX_INTEGER + 1, "invalid_envelope"),
        ("state", "unknown", "invalid_envelope"),
        ("totals", None, "invalid_envelope"),
        ("retain_content", True, "invalid_envelope"),
    ],
)
def test_invalid_heartbeat(field, value, code):
    heartbeat = json.loads(VECTORS["heartbeat"])
    heartbeat[field] = value
    assert_refused(body(heartbeat), code, parser="parse_heartbeat")


@pytest.mark.parametrize("change", [{"expired": True}, {"expired": -1}, {"expired": None}, {"unknown": 0}])
def test_heartbeat_rejects_invalid_loss_totals(change):
    heartbeat = json.loads(VECTORS["heartbeat"])
    heartbeat["totals"].update(change)
    assert_refused(body(heartbeat), "invalid_envelope", parser="parse_heartbeat")


def test_no_untrusted_echo():
    batch, observation = batch_with()
    observation[SENTINEL] = SENTINEL
    error = assert_refused(body(batch), "invalid_row")
    assert SENTINEL not in str(error)
    assert SENTINEL not in repr(error)
    assert SENTINEL not in error.refusal.model_dump_json()
    assert error.__context__ is None
    assert error.__cause__ is None

    malformed = ('{"' + SENTINEL + '": "' + SENTINEL).encode()
    error = assert_refused(malformed, "invalid_envelope")
    assert SENTINEL not in repr(error)
    assert error.__context__ is None
    assert error.__cause__ is None


@pytest.mark.parametrize("kind", ["session.start", "sensor"])
def test_parser_generated_transcript_rows_require_parser_provenance(kind):
    batch, observation = batch_with(TRANSCRIPT)
    observation["kind"] = kind
    assert_refused(body(batch), "invalid_row")


def test_missing_hook_session_requires_a_gap():
    batch, observation = batch_with()
    observation["gaps"].remove("missing_native_session_id")
    assert_refused(body(batch), "invalid_row")


def test_invalid_middle_observation_has_one_row_refusal():
    batch, invalid = batch_with()
    _, before = batch_with(TRANSCRIPT)
    _, after = batch_with("transcript_file_read_B")
    batch["rows"] = [
        {"ordinal": 40, "observation": before},
        {"ordinal": 41, "observation": invalid | {"content": SENTINEL}},
        {"ordinal": 42, "observation": after},
    ]
    assert_refused(body(batch), "invalid_row")


@pytest.mark.parametrize("ordinal", [39, 40])
def test_batch_ordering_error_takes_precedence_over_invalid_observation(ordinal):
    batch, invalid = batch_with()
    _, before = batch_with(TRANSCRIPT)
    _, after = batch_with("transcript_file_read_B")
    batch["rows"] = [
        {"ordinal": 40, "observation": before},
        {"ordinal": ordinal, "observation": invalid | {"content": SENTINEL}},
        {"ordinal": 42, "observation": after},
    ]
    assert_refused(body(batch), "invalid_envelope")


@pytest.mark.parametrize(
    ("name", "source_field"),
    [(HOOK, "native_event"), (TRANSCRIPT, "byte_position")],
)
def test_batch_repeated_source_takes_precedence_over_invalid_observation(name, source_field):
    batch, original = batch_with(name)
    invalid = original | {"source": original["source"] | {source_field: None}}
    batch["rows"].append({"ordinal": 42, "observation": invalid})
    assert_refused(body(batch), "invalid_envelope")


def test_batch_repeated_source_detected_around_invalid_middle_observation():
    batch, first = batch_with(TRANSCRIPT)
    _, invalid = batch_with()
    batch["rows"] = [
        {"ordinal": 40, "observation": first},
        {"ordinal": 41, "observation": invalid | {"content": SENTINEL}},
        {"ordinal": 42, "observation": first},
    ]
    assert_refused(body(batch), "invalid_envelope")


def test_invalid_agent_has_no_source_key_to_compare():
    batch, first = batch_with(TRANSCRIPT)
    batch["rows"].append({"ordinal": 42, "observation": first | {"agent": SENTINEL}})
    assert_refused(body(batch), "invalid_row")


@pytest.mark.parametrize("retain_content", [True, 0, 0.0, "false", None])
def test_heartbeat_ack_retention_is_exactly_false(retain_content):
    ack = json.loads(VECTORS["responses"]["heartbeat_ack"])
    ack["retain_content"] = retain_content
    with pytest.raises(ValueError):
        wire.HeartbeatAck.model_validate(ack)


def test_wire_error_has_a_closed_code_vocabulary():
    with pytest.raises(ValueError, match="^unknown wire refusal code$"):
        wire.WireError(SENTINEL)
