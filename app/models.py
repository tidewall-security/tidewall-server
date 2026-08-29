"""Pydantic v2 models matching the the Tidewall API contract.

These models define the exact shape of requests and responses for the
``/v1/guard_chat_completions`` and ``/v1/unredact`` endpoints.  The field
names and nesting deliberately mirror an industry proprietary API so
that clients (SDK, browser extension) can switch between AIDR-style platforms and Tidewall
without code changes.

Every response model uses ``ConfigDict(extra="allow")`` for forward
compatibility — new fields added by future API versions pass through
without breaking deserialization.

Data flow::

    Client → GuardRequest → guard.py → ScannerEngine → GuardResult → GuardResponse → Client
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# ===================================================================
# Request models
# ===================================================================


#: The event types the product understands, in one place.
#:
#: There were two independent copies of this set -- one in the interaction log,
#: one in the export service -- so adding a sixth type meant finding both, and
#: missing one would have been silent. Both now import this.
EVENT_TYPES = frozenset({"input", "output", "tool_input", "tool_output", "tool_listing"})


class Message(BaseModel):
    """One chat message.

    ``role`` is optional because callers omit it today and the route tolerates
    that. ``content`` must be a string: the route joins message contents, so a
    number or a list has never worked -- it raised inside the handler and
    returned 500 rather than telling the caller their request was malformed.

    Extra fields are allowed. Real OpenAI messages carry ``name``,
    ``tool_calls`` and more, and rejecting them would break callers for no gain:
    this model exists to stop crashes, not to police a vocabulary the product
    does not read.
    """

    model_config = {"extra": "allow"}

    role: str | None = None
    content: str = ""


class GuardInput(BaseModel):
    """The chat payload. Only ``messages`` and ``tools`` are ever read."""

    model_config = {"extra": "allow"}

    messages: list[Message] = []
    tools: list[dict] = []


class GuardRequest(BaseModel):
    """Inbound guard evaluation request.

    ``guard_input`` contains ``{"messages": [...]}`` in OpenAI chat format.
    ``event_type`` controls which detectors run: "input" (pre-LLM),
    "output" (post-LLM), or "tool_listing" (MCP tool filtering).
    """

    guard_input: GuardInput
    #: Constrained here rather than only at logging time. An unknown value used
    #: to run the entire guard and then raise inside `interaction_log`, so the
    #: caller got a 500 after their prompt had already been scanned.
    event_type: Literal["input", "output", "tool_input", "tool_output", "tool_listing"] = "input"
    app_id: str | None = None
    user_id: str | None = None
    llm_provider: str | None = None
    model: str | None = None
    model_version: str | None = None
    source_ip: str | None = None
    source_location: str | None = None
    tenant_id: str | None = None
    collector_instance_id: str | None = None
    extra_info: dict | None = None
    input_fpe_context: str | None = None


class UnredactRequest(BaseModel):
    """Request to reverse a previous redaction."""

    redacted_data: Any
    fpe_context: str


# ===================================================================
# Detector data schemas
# ===================================================================


class AnalyzerResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    analyzer: str
    confidence: float


class MaliciousPromptData(BaseModel):
    model_config = ConfigDict(extra="allow")

    action: str
    analyzer_responses: list[AnalyzerResponse]


class PiiEntity(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str
    value: str
    action: str
    start_pos: int


class ConfidentialAndPiiEntityData(BaseModel):
    model_config = ConfigDict(extra="allow")

    entities: list[PiiEntity]


class SecretAndKeyEntityData(BaseModel):
    model_config = ConfigDict(extra="allow")

    entities: list[PiiEntity]


class MaliciousEntity(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str
    value: str
    start_pos: int
    raw: str


class MaliciousEntityData(BaseModel):
    model_config = ConfigDict(extra="allow")

    entities: list[MaliciousEntity]


class CustomEntityData(BaseModel):
    model_config = ConfigDict(extra="allow")

    entities: list[PiiEntity]


class CompetitorsData(BaseModel):
    model_config = ConfigDict(extra="allow")

    action: str
    entities: list[str]


class LanguageInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    language: str
    confidence: float


class LanguageData(BaseModel):
    model_config = ConfigDict(extra="allow")

    action: str
    languages: list[LanguageInfo]


class TopicInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    topic: str
    confidence: float


class TopicData(BaseModel):
    model_config = ConfigDict(extra="allow")

    action: str
    topics: list[TopicInfo]


class EmojiInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    slug: str
    char: str


class EmojiData(BaseModel):
    model_config = ConfigDict(extra="allow")

    action: str
    emojis: list[EmojiInfo]


class CodeData(BaseModel):
    model_config = ConfigDict(extra="allow")

    action: str
    language: str


# ===================================================================
# Response models
# ===================================================================


class GuardResult(BaseModel):
    """Core verdict from the guard evaluation pipeline.

    ``blocked``: True if a blocker detector fired (prompt rejected).
    ``transformed``: True if any redactor modified the text.
    ``guard_output``: Sanitized messages (only set when transformed=True).
    ``detectors``: Per-detector results keyed by detector name.
    ``access_rules``: Per-rule match results.
    ``fpe_context``: Opaque token for reversing redaction via /v1/unredact.
    ``degraded``: True if part of the scan could not run.
    ``failed_detectors``: Names of detectors that failed or ran incompletely.
    """

    model_config = ConfigDict(extra="allow")

    blocked: bool
    transformed: bool
    guard_output: dict | None = None
    policy: str
    detectors: dict = Field(default_factory=dict)
    access_rules: dict = Field(default_factory=dict)
    fpe_context: str | None = None
    # True when some part of the scan could not run. A caller must be able to
    # tell "checked, found nothing" from "could not check" without digging into
    # per-detector status — under on_detector_failure=report this flag and the
    # summary are the only signals it gets.
    degraded: bool = False
    failed_detectors: list[str] = Field(default_factory=list)


class GuardResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    request_id: str
    request_time: str
    response_time: str
    status: str
    summary: str
    result: GuardResult


class UnredactResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    data: Any


class UnredactResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    request_id: str
    request_time: str
    response_time: str
    status: str
    summary: str
    result: UnredactResult
