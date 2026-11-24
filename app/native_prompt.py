"""Closed, bounded wire representations for the qualified native prompt callback."""

import json
from dataclasses import asdict
from datetime import datetime
from typing import Annotated, ClassVar, Literal, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.agent_events import _check_json_depth, _reject_nonfinite, _unique_object
from app.services.prompt_classifier_client import MODEL_IDENTITY, RESERVED_TOKENS

UUID4 = Annotated[
    str, Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", max_length=36)
]
Hex64 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$", max_length=64)]
Version = Annotated[int, Field(ge=1, le=1)]
Generation = Annotated[int, Field(ge=1, le=9_007_199_254_740_991)]
Counter = Annotated[int, Field(ge=0, le=2_147_483_647)]
Score = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
Profile = Literal["tidewall.prompt-injection.1"]
SourceProfile = Literal["claude-code.user-prompt-submit.1"]
InputState = Literal["complete", "capture_disabled", "input_too_large", "unsupported"]
Reason = Literal[
    "clean",
    "classifier_positive",
    "access_rule_block",
    "malicious_list",
    "benign_override",
    "capture_disabled",
    "input_too_large",
    "input_unsupported",
    "classifier_unavailable",
    "classifier_invalid",
    "prompt_list_failed",
    "deadline_exceeded",
    "policy_changed",
    "policy_unsupported",
    "authority_changed",
    "storage_unavailable",
    "request_retired",
]
ErrorCode = Literal[
    "invalid_request",
    "unauthorized",
    "grant_expired",
    "grant_revoked",
    "identity_conflict",
    "request_retired",
    "deadline_exceeded",
    "policy_changed",
    "policy_unsupported",
    "capacity",
    "storage_unavailable",
]
Stage = Literal[
    "stdout_flushed",
    "allow_no_output",
    "stdout_failed",
    "native_ack_blocked",
    "effect_allow_marker_verified",
    "effect_deny_no_effect_verified",
    "unknown",
]


class NativeError(ValueError):
    def __init__(self, code: ErrorCode, status: int = 422):
        super().__init__(code)
        self.code = code
        self.status = status


class WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)
    byte_limit: ClassVar[int] = 2048


class NativeMetadata(WireModel):
    version: Version
    occurrence_id: UUID4
    agent: Literal["claude-code"]
    native_profile: SourceProfile
    agent_version: Literal["2.1.330"]
    session_token: Hex64


class NativePromptRequest(WireModel):
    byte_limit = 16_384
    version: Version
    request_id: UUID4
    observation: NativeMetadata
    input_state: InputState
    budget_ms: Annotated[int, Field(ge=1, le=1800)]
    prompt: Annotated[str, Field(min_length=1, max_length=8000)] | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def check_input(self) -> Self:
        if self.input_state == "complete":
            if (
                self.prompt is None
                or not self.prompt.strip()
                or len(self.prompt.encode("utf-8")) > 8000
                or any(token in self.prompt for token in RESERVED_TOKENS)
            ):
                raise ValueError("invalid complete prompt")
        elif "prompt" in self.model_fields_set:
            raise ValueError("omit prompt")
        return self


class NativePolicySettings(WireModel):
    enabled: bool
    profile: Profile = "tidewall.prompt-injection.1"
    threshold: Score = 0.5


class NativeGrantRequest(WireModel):
    device_id: UUID4
    session_token: Hex64
    native_profile: SourceProfile
    ttl_seconds: Annotated[int, Field(ge=1, le=1800)]
    capture_allowed: bool = False
    session_id: UUID4 | None = None

    @model_validator(mode="after")
    def check_session(self) -> Self:
        if self.capture_allowed != ("session_id" in self.model_fields_set) or (
            self.capture_allowed and self.session_id is None
        ):
            raise ValueError("capture requires a selected session")
        return self


class NativeConfigAck(NativePolicySettings):
    policy_id: str
    generation: Generation
    profile: Profile
    threshold: Score


class NativeGrantIssued(WireModel):
    capability: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$", max_length=43, repr=False)]
    grant_id: UUID4
    grant_generation: Generation
    policy_generation: Generation
    policy_id: str
    device_id: UUID4
    native_profile: SourceProfile
    session_token: Hex64
    session_id: UUID4 | None
    capture_allowed: bool
    expires_at: Annotated[
        str, Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\+00:00$", max_length=32)
    ]

    @model_validator(mode="after")
    def check_selected_session(self) -> Self:
        datetime.fromisoformat(self.expires_at)
        if self.capture_allowed != (self.session_id is not None):
            raise ValueError("invalid selected session")
        return self


class NativeObservationAck(WireModel):
    version: Version
    occurrence_id: UUID4
    event_id: UUID4
    session_id: UUID4


# Canonical representation admitted by migration 9a42c7d3e601.
MODEL_IDENTITY_JSON = json.dumps(asdict(MODEL_IDENTITY), sort_keys=True, separators=(",", ":"))


class PinnedModel(WireModel):
    base: Literal["Qwen/Qwen3-0.6B"]
    base_revision: Literal["c1899de289a04d12100db370d81485cdf75e47ca"]
    tokenizer_revision: Literal["c1899de289a04d12100db370d81485cdf75e47ca"]
    adapter: Literal["abedegno/prompt-injection-classifier-qwen3-0p6b"]
    adapter_revision: Literal["5500c3bef53729ed4661b5cfae1b01adca96ca4c"]
    prompt_sha256: Literal["3a0e693064509eb24773ba53af4831ecb4c6ca8cf741a28d2d10080384df5041"]
    scoring_implementation: Literal["qwen3_last_token_logits.1"]
    class_token_ids: Annotated[list[int], Field(json_schema_extra={"const": list(MODEL_IDENTITY.class_token_ids)})]

    @model_validator(mode="after")
    def check_tokens(self) -> Self:
        if tuple(self.class_token_ids) != MODEL_IDENTITY.class_token_ids:
            raise ValueError("invalid model identity")
        return self


class Assessed(WireModel):
    status: Literal["assessed"]
    reason: Literal["clean", "classifier_positive"]
    profile: Profile
    model_identity: PinnedModel
    unsafe_score: Score
    score_kind: Literal["two_class_softmax_uncalibrated"]
    input_tokens: Annotated[int, Field(ge=1, le=1024)]


class NotRequested(WireModel):
    status: Literal["not_requested"]
    reason: Literal["access_rule_block", "malicious_list", "benign_override", "capture_disabled"]
    profile: Profile


class Unsupported(WireModel):
    status: Literal["unsupported"]
    reason: Literal["input_unsupported", "input_too_large"]
    profile: Profile


class Unavailable(WireModel):
    status: Literal["unavailable"]
    reason: Literal[
        "classifier_unavailable",
        "deadline_exceeded",
        "policy_changed",
        "policy_unsupported",
        "authority_changed",
        "storage_unavailable",
        "request_retired",
    ]
    profile: Profile


class Failed(WireModel):
    status: Literal["failed"]
    reason: Literal["classifier_invalid", "prompt_list_failed"]
    profile: Profile


class NativeDecisionReply(WireModel):
    byte_limit = 8192
    version: Version
    request_id: UUID4
    occurrence_id: UUID4
    decision_id: UUID4
    event_id: UUID4
    session_id: UUID4
    grant_id: UUID4
    grant_generation: Generation
    policy_revision: Hex64
    mode: Literal["report", "enforce"]
    assessment: Annotated[Assessed | NotRequested | Unsupported | Unavailable | Failed, Field(discriminator="status")]
    evaluated_action: Literal["allow", "deny", "unknown"]
    returned_action: Literal["allow", "deny"] | None
    reason: Reason

    @model_validator(mode="after")
    def check_outcome(self) -> Self:
        rule_over_unsupported = self.reason == "access_rule_block" and self.assessment.status == "unsupported"
        if self.reason != self.assessment.reason and not rule_over_unsupported:
            raise ValueError("inconsistent assessment and decision reason")
        if self.assessment.status in ("failed", "unsupported", "unavailable") and self.returned_action is not None:
            if (self.evaluated_action, self.returned_action) not in {("deny", "deny"), ("unknown", "allow")}:
                raise ValueError("inconsistent incomplete assessment action")
        if self.returned_action == "deny" and self.evaluated_action != "deny":
            raise ValueError("inconsistent deny")
        if self.reason in ("classifier_positive", "malicious_list"):
            if self.evaluated_action == "unknown":
                raise ValueError("a finding requires a known evaluation")
            expected = "allow" if self.mode == "report" else self.evaluated_action
            if self.returned_action is not None and self.returned_action != expected:
                raise ValueError("inconsistent finding action")
        if self.reason == "access_rule_block" and (self.evaluated_action != "deny" or self.returned_action == "allow"):
            raise ValueError("inconsistent access rule decision")
        if self.reason in ("clean", "capture_disabled", "benign_override") and self.evaluated_action != "allow":
            raise ValueError("inconsistent allow")
        if (
            self.reason
            in ("policy_changed", "policy_unsupported", "authority_changed", "storage_unavailable", "request_retired")
            and self.returned_action is not None
        ):
            raise ValueError("unavailable authority or storage cannot supply a directive")
        return self


class NativeRefusal(WireModel):
    byte_limit = 256
    version: Version
    request_id: UUID4 | None
    code: ErrorCode


class NativeDeliveryReport(WireModel):
    report_id: UUID4
    decision_id: UUID4
    request_id: UUID4
    occurrence_id: UUID4
    evidence_source: Literal["hook", "controlled_observer"]
    stage: Stage
    tool_count: Counter | None = None
    token_count: Counter | None = None
    marker_present: bool | None = None

    @model_validator(mode="after")
    def check_evidence(self) -> Self:
        for key in ("tool_count", "token_count", "marker_present"):
            if key in self.model_fields_set and getattr(self, key) is None:
                raise ValueError("omit absent evidence")
        return self


class NativeDeliveryAck(WireModel):
    version: Version
    report_id: UUID4
    decision_id: UUID4


T = TypeVar("T", bound=WireModel)


def parse_wire(data: bytes, dto: type[T]) -> T:
    """Reject framing or schema ambiguity without retaining validation exceptions."""
    if len(data) <= dto.byte_limit:
        try:
            decoded = data.decode("utf-8")
            _check_json_depth(decoded)
            obj = json.loads(decoded, object_pairs_hook=_unique_object, parse_constant=_reject_nonfinite)
            return dto.model_validate(obj)
        except ValueError:
            pass
    raise NativeError("invalid_request")
