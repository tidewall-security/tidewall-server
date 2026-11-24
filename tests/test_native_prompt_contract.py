import json
from pathlib import Path
from uuid import uuid4

import pytest
from jsonschema import Draft202012Validator

META = dict(
    version=1,
    occurrence_id="12345678-abcd-4000-8000-000000000001",
    agent="claude-code",
    native_profile="claude-code.user-prompt-submit.1",
    agent_version="2.1.330",
    session_token="a" * 64,
)
DECISION = dict(
    version=1, request_id=str(uuid4()), observation=META, input_state="complete", prompt=" É  ", budget_ms=1800
)


def test_exact_prompt_roundtrip():
    from app.native_prompt import NativePromptRequest, parse_wire

    assert parse_wire(json.dumps(DECISION).encode(), NativePromptRequest).prompt == " É  "


@pytest.mark.parametrize(
    "raw",
    [
        b'{"version":1,"version":1}',
        b"\xff",
        json.dumps({**META, "version": True}).encode(),
        json.dumps({**META, "version": 1.0}).encode(),
        json.dumps({**META, "agent_version": "2.1.329"}).encode(),
        json.dumps({**META, "native_profile": "claude-fixture-v1"}).encode(),
        json.dumps({**META, "session_token": "A" * 64}).encode(),
        json.dumps({**META, "path": "synthetic-private"}).encode(),
        json.dumps({**META, "occurrence_id": "12345678-abcd-1000-8000-000000000001"}).encode(),
    ],
)
def test_strict_metadata(raw):
    from app.native_prompt import NativeError, NativeMetadata, parse_wire

    with pytest.raises(NativeError, match="invalid_request"):
        parse_wire(raw, NativeMetadata)


@pytest.mark.parametrize(
    "overrides",
    [
        dict(budget_ms=True),
        dict(budget_ms=1801),
        dict(input_state="capture_disabled"),
        dict(input_state="unsupported", prompt=None),
        dict(prompt=""),
        dict(prompt="a" * 8001),
        dict(prompt="\udcff"),
        dict(prompt="<|im_start|>"),
        dict(device_id="extra"),
    ],
)
def test_strict_decision(overrides):
    from app.native_prompt import NativeError, NativePromptRequest, parse_wire

    with pytest.raises(NativeError):
        parse_wire(json.dumps({**DECISION, **overrides}).encode(), NativePromptRequest)


def test_size_before_parsing():
    from app.native_prompt import NativeError, NativePromptRequest, parse_wire

    raw = json.dumps(DECISION).encode().ljust(16384)
    assert parse_wire(raw, NativePromptRequest).budget_ms == 1800
    with pytest.raises(NativeError):
        parse_wire(raw + b" ", NativePromptRequest)


def _unique_vector_object(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate field")
    return obj


def test_published_vectors():
    from app import native_prompt as wire

    root = Path(__file__).resolve().parents[1] / "contracts"
    schema = json.loads((root / "native_prompt_v1.json").read_bytes())
    assert "prompt_list_failed" in json.dumps(schema)
    vectors = json.loads((root / "native_prompt_v1_vectors.json").read_bytes())
    Draft202012Validator.check_schema(schema)
    requests = {
        fields[0]: schema["x-request-max-bytes"][path] for path, fields in schema["x-endpoints"].items() if fields[0]
    }
    for item in vectors:
        dto = getattr(wire, item["type"])
        raw = bytes.fromhex(item["hex"])
        definition = schema["$defs"][item["type"]]
        limit = requests.get(item["type"], definition.get("x-max-utf8-json-bytes"))
        assert limit == dto.byte_limit
        # JSON Schema operates on decoded values. Check wire framing independently first.
        try:
            obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_vector_object)
        except ValueError:
            accepted = False
        else:
            accepted = len(raw) <= limit and _schema_validator(schema, item["type"]).is_valid(obj)
            if accepted and item["type"] == "NativePromptRequest" and "prompt" in obj:
                prompt = obj["prompt"]
                constraints = definition["properties"]["prompt"]
                accepted = (
                    len(prompt.encode()) <= constraints["x-max-decoded-utf8-bytes"]
                    and bool(prompt.strip())
                    and all(t not in prompt for t in constraints["x-forbidden-substrings"])
                )
        assert accepted is item["valid"], item["name"]
        if item["valid"]:
            wire.parse_wire(raw, dto)
        else:
            with pytest.raises(wire.NativeError):
                wire.parse_wire(raw, dto)


def test_reply_refuses_inconsistent_deny_and_preserves_independent_metadata_block():
    from app.native_prompt import NativeDecisionReply, NativeError, parse_wire

    ids = {
        key: str(uuid4())
        for key in ("request_id", "occurrence_id", "event_id", "session_id", "decision_id", "grant_id")
    }
    base = dict(
        version=1,
        **ids,
        grant_generation=1,
        mode="report",
        policy_revision="c" * 64,
        assessment=dict(status="unsupported", profile="tidewall.prompt-injection.1", reason="input_too_large"),
        reason="access_rule_block",
        evaluated_action="deny",
        returned_action="deny",
    )
    assert parse_wire(json.dumps(base).encode(), NativeDecisionReply).reason == "access_rule_block"
    for changes in [dict(evaluated_action="allow"), dict(reason="classifier_positive"), dict(returned_action="allow")]:
        with pytest.raises(NativeError):
            parse_wire(json.dumps({**base, **changes}).encode(), NativeDecisionReply)


def test_refusal_only_echoes_valid_request_identity():
    from app.native_prompt import NativeError
    from app.routes.native_prompt import native_refusal

    rid = str(uuid4())
    assert json.loads(native_refusal(NativeError("identity_conflict", 409), rid).body)["request_id"] == rid
    response = native_refusal(NativeError("invalid_request"), "untrusted" * 300)
    assert len(response.body) <= 256
    assert json.loads(response.body) == dict(version=1, request_id=None, code="invalid_request")


def test_successful_report_finding_is_observational_and_failure_can_enforce():
    from app.native_prompt import NativeDecisionReply, NativeError, parse_wire

    ids = {
        key: str(uuid4())
        for key in ("request_id", "occurrence_id", "event_id", "session_id", "decision_id", "grant_id")
    }
    reply = dict(
        version=1,
        **ids,
        grant_generation=1,
        mode="report",
        policy_revision="c" * 64,
        assessment=dict(status="not_requested", profile="tidewall.prompt-injection.1", reason="malicious_list"),
        reason="malicious_list",
        evaluated_action="deny",
        returned_action="deny",
    )
    with pytest.raises(NativeError):
        parse_wire(json.dumps(reply).encode(), NativeDecisionReply)
    reply["assessment"].update(status="failed", reason="prompt_list_failed")
    reply["reason"] = "prompt_list_failed"
    assert parse_wire(json.dumps(reply).encode(), NativeDecisionReply).returned_action == "deny"


def test_published_standalone_endpoint_byte_limits():
    from app.native_prompt import NativeError, NativeMetadata, NativePromptRequest, parse_wire

    root = Path(__file__).resolve().parents[1] / "contracts"
    schema = json.loads((root / "native_prompt_v1.json").read_bytes())
    cap = schema["x-request-max-bytes"]
    for route, dto, size, payload in [
        ("POST /v1/native-prompt/observations", NativeMetadata, 2048, META),
        ("POST /v1/native-prompt/decisions", NativePromptRequest, 16384, DECISION),
    ]:
        assert cap[route] == size
        assert schema["x-endpoints"][route][0] == dto.__name__
        raw = json.dumps(payload).encode().ljust(size)
        assert parse_wire(raw, dto)
        with pytest.raises(NativeError):
            parse_wire(raw + b" ", dto)


def _schema_validator(schema, name):
    return Draft202012Validator({"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": "#/$defs/" + name})


@pytest.mark.parametrize(
    ("evaluated", "returned", "valid"),
    [
        ("deny", "allow", False),
        ("allow", "allow", False),
        ("unknown", "deny", False),
        ("deny", "deny", True),
        ("unknown", "allow", True),
        ("unknown", None, True),
    ],
)
@pytest.mark.parametrize(
    ("status", "reason"),
    [("failed", "prompt_list_failed"), ("unsupported", "input_too_large"), ("unavailable", "classifier_unavailable")],
)
def test_incomplete_action_pairs_in_dto_and_published_schema(evaluated, returned, valid, status, reason):
    from app.native_prompt import NativeDecisionReply, NativeError, parse_wire

    root = Path(__file__).resolve().parents[1] / "contracts"
    published = json.loads((root / "native_prompt_v1.json").read_bytes())
    vectors = json.loads((root / "native_prompt_v1_vectors.json").read_bytes())
    reply = json.loads(bytes.fromhex(next(v["hex"] for v in vectors if v["name"] == "valid NativeDecisionReply")))
    reply.update(
        assessment=dict(profile="tidewall.prompt-injection.1", reason=reason, status=status),
        reason=reason,
        evaluated_action=evaluated,
        returned_action=returned,
    )
    matches = _schema_validator(published, "NativeDecisionReply").is_valid(reply)
    assert matches is valid
    if valid:
        parse_wire(json.dumps(reply).encode(), NativeDecisionReply)
    else:
        with pytest.raises(NativeError):
            parse_wire(json.dumps(reply).encode(), NativeDecisionReply)
