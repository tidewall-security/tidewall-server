# SPDX-License-Identifier: Apache-2.0
# Adapted from OpenAIDR src/openaidr/server/prompt_classifier.py,
# blob 82e9f2e47b1a111312839043a0d02b01b7f8854a. Copyright 2026 OpenSecura, Inc.
"""Single-prompt client for the pinned Tidewall inference service."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import os
import ssl
import stat
import time
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

import httpx

if TYPE_CHECKING:
    from app.config import Settings

PROFILE = "tidewall.prompt-injection.1"
SCORE_KIND = "two_class_softmax_uncalibrated"
RESERVED_TOKENS = (
    "<|endoftext|>",
    "<|im_start|>",
    "<|im_end|>",
    "<|object_ref_start|>",
    "<|object_ref_end|>",
    "<|box_start|>",
    "<|box_end|>",
    "<|quad_start|>",
    "<|quad_end|>",
    "<|vision_start|>",
    "<|vision_end|>",
    "<|vision_pad|>",
    "<|image_pad|>",
    "<|video_pad|>",
)


@dataclass(frozen=True)
class ModelIdentity:
    base: str
    base_revision: str
    adapter: str
    adapter_revision: str
    tokenizer_revision: str
    prompt_sha256: str
    class_token_ids: tuple[int, ...]
    scoring_implementation: str


MODEL_IDENTITY = ModelIdentity(
    base="Qwen/Qwen3-0.6B",
    base_revision="c1899de289a04d12100db370d81485cdf75e47ca",
    adapter="abedegno/prompt-injection-classifier-qwen3-0p6b",
    adapter_revision="5500c3bef53729ed4661b5cfae1b01adca96ca4c",
    tokenizer_revision="c1899de289a04d12100db370d81485cdf75e47ca",
    prompt_sha256="3a0e693064509eb24773ba53af4831ecb4c6ca8cf741a28d2d10080384df5041",
    class_token_ids=(38157, 18675, 19860, 6092),
    scoring_implementation="qwen3_last_token_logits.1",
)


@dataclass(frozen=True)
class CompletePrompt:
    text: str = field(repr=False)


AssessmentStatus = Literal["assessed", "unsupported", "unavailable", "failed"]
AssessmentReason = Literal[
    "input_unsupported", "input_too_large", "classifier_unavailable", "classifier_invalid", "deadline_exceeded"
]


@dataclass(frozen=True)
class AssessmentResult:
    status: AssessmentStatus
    reason: AssessmentReason | None
    profile: str = PROFILE
    model_identity: ModelIdentity | None = None
    unsafe_score: float | None = None
    score_kind: str | None = None
    input_tokens: int | None = None


@dataclass(frozen=True)
class ClassifierSettings:
    origin: str = field(repr=False)
    tenant_id: str = field(repr=False)
    key_file: str = field(repr=False)
    timeout_ms: int = 1200
    ca_file: str | None = field(default=None, repr=False)
    allow_loopback_http: bool = False

    def __post_init__(self) -> None:
        try:
            url = urlsplit(self.origin)
            host = url.hostname
            if (
                not host
                or not self.origin.isascii()
                or any(ord(c) < 33 or ord(c) == 127 for c in self.origin)
                or any(c in self.origin for c in "@?#\\%")
                or url.path
                or url.netloc.endswith(":")
                or url.port == 0
                or url.scheme not in {"https", "http"}
            ):
                raise ValueError
            parsed = httpx.URL(self.origin)
            default_port = 443 if url.scheme == "https" else 80
            expected_port = None if url.port == default_port else url.port
            if parsed.host != host or parsed.port != expected_port:
                raise ValueError
            if type(self.allow_loopback_http) is not bool:
                raise ValueError
            if url.scheme == "http" and (not self.allow_loopback_http or not ipaddress.ip_address(host).is_loopback):
                raise ValueError
            if str(UUID(self.tenant_id)) != self.tenant_id or not self.key_file:
                raise ValueError
            if type(self.timeout_ms) is not int or not 1 <= self.timeout_ms <= 1500:
                raise ValueError
        except (AttributeError, ValueError, TypeError, httpx.InvalidURL):
            raise ValueError("Invalid native classifier origin, tenant, key-file, or timeout setting") from None

    @classmethod
    def from_settings(cls, settings: Settings) -> ClassifierSettings | None:
        fields = settings.model_fields_set
        if not any(name.startswith("NATIVE_CLASSIFIER_") for name in fields):
            return None
        origin, tenant, key = (
            settings.NATIVE_CLASSIFIER_ORIGIN,
            settings.NATIVE_CLASSIFIER_TENANT_ID,
            settings.NATIVE_CLASSIFIER_KEY_FILE,
        )
        if not origin or not tenant or not key:
            raise ValueError("Native classifier requires origin, tenant ID and key file")
        return cls(
            origin,
            tenant,
            key,
            settings.NATIVE_CLASSIFIER_TIMEOUT_MS,
            settings.NATIVE_CLASSIFIER_CA_FILE,
            settings.NATIVE_CLASSIFIER_ALLOW_LOOPBACK_HTTP,
        )


def _read_key(path: str) -> str:
    # Nonblocking open followed by fstat also rejects a misconfigured FIFO without hanging startup.
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError
            raw = stream.read(4097)
        key = raw.strip().decode("ascii")
        if len(raw) > 4096 or len(key) < 32 or any(not 33 <= ord(c) <= 126 for c in key):
            raise ValueError
        return key
    except (OSError, ValueError):
        raise ValueError("Invalid native classifier service key file") from None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError
        obj[key] = value
    return obj


_INVALID = AssessmentResult("failed", "classifier_invalid")
_UNAVAILABLE = AssessmentResult("unavailable", "classifier_unavailable")
_DEADLINE = AssessmentResult("unavailable", "deadline_exceeded")
_TOO_LARGE = AssessmentResult("unsupported", "input_too_large")
_UNSUPPORTED = AssessmentResult("unsupported", "input_unsupported")

# Mirrors tidewall_lora.api.STATUS and RETRYABLE at standalone release 334e171.
_ERRORS = {
    "invalid_request": (422, False, _INVALID),
    "unsupported_input": (422, False, _UNSUPPORTED),
    "input_too_large": (413, False, _TOO_LARGE),
    "unauthenticated": (401, False, _UNAVAILABLE),
    "tenant_mismatch": (403, False, _UNAVAILABLE),
    "model_unavailable": (503, True, _UNAVAILABLE),
    "capacity_exceeded": (503, True, _UNAVAILABLE),
    "deadline_exceeded": (504, True, _DEADLINE),
    "request_conflict": (409, False, _INVALID),
}
# Only the service's admission boundary can refuse before decoding a request ID.
_NULL_ID_CODES = {"invalid_request", "input_too_large", "unauthenticated", "tenant_mismatch", "deadline_exceeded"}
_ERROR_FIELDS = {"schema_version", "profile", "request_id", "status", "code", "retryable"}
_CLASSIFIED_FIELDS = {
    "schema_version",
    "profile",
    "request_id",
    "status",
    "unsafe_score",
    "score_kind",
    "model",
    "input_tokens",
    "inference_ms",
}


def _result(body: bytes | bytearray, status: int, request_id: str) -> AssessmentResult:
    obj = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(obj, dict) or type(obj.get("schema_version")) is not int or obj["schema_version"] != 1:
        return _INVALID
    if obj.get("profile") != PROFILE:
        return _INVALID
    if status != 200:
        if set(obj) != _ERROR_FIELDS or obj["status"] != "error" or type(obj["code"]) is not str:
            return _INVALID
        code = obj["code"]
        expected = _ERRORS.get(code)
        if expected is None or status != expected[0] or obj["retryable"] is not expected[1]:
            return _INVALID
        if code in {"unauthenticated", "tenant_mismatch"} and obj["request_id"] is not None:
            return _INVALID
        if obj["request_id"] != request_id and not (obj["request_id"] is None and code in _NULL_ID_CODES):
            return _INVALID
        return expected[2]
    if set(obj) != _CLASSIFIED_FIELDS or obj["request_id"] != request_id or obj["status"] != "classified":
        return _INVALID
    score, elapsed, tokens = obj["unsafe_score"], obj["inference_ms"], obj["input_tokens"]
    if (
        type(score) not in (int, float)
        or not 0 <= score <= 1
        or not math.isfinite(score)
        or type(tokens) is not int
        or not 1 <= tokens <= 1024
        or type(elapsed) not in (int, float)
        or not 0 <= elapsed <= 1e9
        or not math.isfinite(elapsed)
        or obj["score_kind"] != SCORE_KIND
    ):
        return _INVALID
    model = obj["model"]
    expected_model = asdict(MODEL_IDENTITY)
    expected_model["class_token_ids"] = list(MODEL_IDENTITY.class_token_ids)
    if model != expected_model or any(type(token) is not int for token in model["class_token_ids"]):
        return _INVALID
    return AssessmentResult("assessed", None, PROFILE, MODEL_IDENTITY, float(score), SCORE_KIND, tokens)


class PromptClassifierClient:
    def __init__(self, settings: ClassifierSettings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        key = _read_key(settings.key_file)
        try:
            verify = ssl.create_default_context(cafile=settings.ca_file)
        except (OSError, ValueError):
            raise ValueError("Invalid native classifier CA file") from None
        self._timeout_ms = settings.timeout_ms
        self._http = httpx.AsyncClient(
            base_url=settings.origin,
            trust_env=False,
            follow_redirects=False,
            verify=verify,
            transport=transport,
            headers={
                "Authorization": "Bearer " + key,
                "Accept-Encoding": "identity",
                "X-Tidewall-Tenant-ID": settings.tenant_id,
            },
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def assess(self, prompt: CompletePrompt, *, request_id: UUID, deadline: float) -> AssessmentResult:
        """Assess one exact prompt under the original Server deadline, including its 150 ms reserve."""
        start = time.monotonic()
        if not math.isfinite(deadline):
            return _DEADLINE
        finish_by = min(start + self._timeout_ms / 1000, deadline - 0.150)
        if finish_by <= start:
            return _DEADLINE
        if not isinstance(request_id, UUID):
            return _INVALID
        if not isinstance(prompt, CompletePrompt) or type(prompt.text) is not str:
            return _UNSUPPORTED
        text = prompt.text
        if len(text) > 8000:
            return _TOO_LARGE
        try:
            if len(text.encode("utf-8")) > 8000:
                return _TOO_LARGE
        except UnicodeEncodeError:
            return _UNSUPPORTED
        if not text.strip() or any(token in text for token in RESERVED_TOKENS):
            return _UNSUPPORTED

        ident = str(request_id)
        budget_ms = int((finish_by - time.monotonic()) * 1000)
        if budget_ms < 1:
            return _DEADLINE
        body = {
            "schema_version": 1,
            "profile": PROFILE,
            "request_id": ident,
            "event_kind": "prompt",
            "messages": [{"role": "user", "content": text}],
            "timeout_ms": budget_ms,
        }
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(payload) > 12000:
            return _TOO_LARGE
        seconds = finish_by - time.monotonic()
        if seconds <= 0:
            return _DEADLINE
        try:
            async with asyncio.timeout(seconds):
                async with self._http.stream(
                    "POST",
                    "/v1/classify",
                    content=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=seconds,
                ) as response:
                    if (
                        response.headers.get("content-encoding", "identity").lower() != "identity"
                        or len(response.headers.get_list("content-type")) != 1
                        or response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                        != "application/json"
                    ):
                        return _INVALID
                    content = bytearray()
                    async for chunk in response.aiter_raw():
                        if len(chunk) > 8192 - len(content):
                            return _INVALID
                        content.extend(chunk)
                result = _result(content, response.status_code, ident)
            return _DEADLINE if time.monotonic() >= finish_by else result
        except (TimeoutError, httpx.TimeoutException):
            return _DEADLINE
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            return _INVALID
        except httpx.HTTPError:
            return _UNAVAILABLE
