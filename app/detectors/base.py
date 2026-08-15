"""Abstract base for all Tidewall detectors.

Every detector in the system (malicious_prompt, pii, secrets, topic, etc.)
inherits from ``BaseDetector`` and implements two things:

    1. ``name`` — a string matching the detector key in policy YAML
    2. ``scan(text, **kwargs)`` — returns a ``DetectorResult``

The ``action`` field (from policy config) determines how the ScannerEngine
treats a positive detection:

    - ``"block"``  → short-circuit, request is rejected
    - ``"redact"`` → mutate text (e.g. replace PII), continue pipeline
    - ``"report"`` → flag but don't modify, continue pipeline

Detectors are instantiated once at startup by ``scanner_engine._make_detector``
and reused across all requests.  They must be thread-safe (guard requests
run in ``asyncio.to_thread``).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DetectorStatus(str, Enum):
    """Whether a detector's verdict can be trusted.

    Before this existed, a detector that could not run returned
    ``DetectorResult(detected=False)`` — indistinguishable from one that ran
    and found nothing. A broken scanner therefore looked exactly like a clean
    scan and the request was allowed through with "No threats detected". That
    is P0-2, and this enum is the value that makes the two cases separable.
    """

    OK = "ok"
    """Ran to completion; the verdict is trustworthy."""

    FAILED = "failed"
    """Could not run, or produced unusable output. There is no verdict."""

    SKIPPED = "skipped"
    """Deliberately not run. Carries a :class:`SkipReason`."""


class FailureCode(str, Enum):
    """Why a detector failed.

    Deliberately coarse and enumerated. Exception text must never reach a
    response, an audit row, or a metric label — it is logged once at the server
    boundary and reduced to one of these codes everywhere else.
    """

    DETECTOR_UNKNOWN = "detector_unknown"
    IMPORT_FAILED = "import_failed"
    DEPENDENCY_MISSING = "dependency_missing"
    MODEL_LOAD_FAILED = "model_load_failed"
    CONSTRUCT_FAILED = "construct_failed"
    CONFIG_INVALID = "config_invalid"
    SCAN_FAILED = "scan_failed"
    OUTPUT_INVALID = "output_invalid"
    REDACTION_FAILED = "redaction_failed"
    RECONSTRUCTION_FAILED = "reconstruction_failed"


class SkipReason(str, Enum):
    """Why a detector was deliberately not run.

    A skip is a policy outcome, not a failure, and must never contribute to a
    degraded verdict.
    """

    NOT_ENABLED = "not_enabled"
    WRONG_EVENT_TYPE = "wrong_event_type"
    SHORT_CIRCUITED = "short_circuited"
    NO_INPUT = "no_input"


@dataclass
class ComponentStatus:
    """Status of one sub-detector inside a composite."""

    status: DetectorStatus = DetectorStatus.OK
    failure_code: FailureCode | None = None
    skip_reason: SkipReason | None = None


@dataclass
class DetectorResult:
    """Result from a single detector scan.

    Attributes:
        detected: True if the detector found something noteworthy. Meaningful
            only when ``status`` is OK.
        data: Detector-specific payload (entities, analyzer responses, etc.).
        sanitized_text: Modified text after redaction.  Only set by detectors
            with ``action="redact"`` (PII, secrets, custom_entity).
        status: Whether this verdict can be trusted at all.
        failure_code: Set when ``status`` is FAILED.
        skip_reason: Set when ``status`` is SKIPPED.
        components: Per-sub-detector status, for composite detectors.
    """

    detected: bool = False
    data: dict[str, Any] | None = None
    sanitized_text: str | None = None
    status: DetectorStatus = DetectorStatus.OK
    failure_code: FailureCode | None = None
    skip_reason: SkipReason | None = None
    components: dict[str, ComponentStatus] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # A failed detector has no verdict. Allowing detected=True alongside
        # FAILED would let a degraded result masquerade as a detection, which
        # is the mirror image of the bug this type exists to close.
        if self.status is DetectorStatus.FAILED:
            if self.detected:
                raise ValueError("DetectorResult cannot be both FAILED and detected")
            if self.failure_code is None:
                raise ValueError("FAILED DetectorResult requires a failure_code")
        if self.status is DetectorStatus.SKIPPED and self.skip_reason is None:
            raise ValueError("SKIPPED DetectorResult requires a skip_reason")

    @property
    def trustworthy(self) -> bool:
        """True if this result can be relied on for an enforcement decision."""
        return self.status is not DetectorStatus.FAILED

    @classmethod
    def failed(cls, code: FailureCode, data: dict[str, Any] | None = None) -> DetectorResult:
        """Construct a FAILED result — the only supported way to report failure."""
        return cls(detected=False, data=data, status=DetectorStatus.FAILED, failure_code=code)

    @classmethod
    def skipped(cls, reason: SkipReason) -> DetectorResult:
        """Construct a SKIPPED result."""
        return cls(detected=False, status=DetectorStatus.SKIPPED, skip_reason=reason)


class BaseDetector(ABC):
    """Base class for all Tidewall detectors.

    Subclasses must implement ``name`` and ``scan()``.  The ``can_block``
    and ``can_redact`` properties are derived from the policy's ``action``
    setting and used by the ScannerEngine to decide control flow.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.action = config.get("action", "report")

    @property
    @abstractmethod
    def name(self) -> str:
        """Detector name — must match the key in policy YAML."""
        ...

    @abstractmethod
    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        """Scan text and return detection result.

        kwargs may include detector-specific context (e.g. ``vault`` for PII,
        ``tools`` for MCP validation, ``messages`` for intent conformance).
        """
        ...

    @property
    def can_block(self) -> bool:
        """True if this detector's action is 'block' (short-circuits the pipeline)."""
        return bool(self.action == "block")

    @property
    def can_redact(self) -> bool:
        """True if this detector's action is 'redact' (mutates text in-flight)."""
        return bool(self.action == "redact")
