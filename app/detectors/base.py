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
from dataclasses import dataclass
from typing import Any


@dataclass
class DetectorResult:
    """Result from a single detector scan.

    Attributes:
        detected: True if the detector found something noteworthy.
        data: Detector-specific payload (entities, analyzer responses, etc.).
        sanitized_text: Modified text after redaction.  Only set by detectors
            with ``action="redact"`` (PII, secrets, custom_entity).
    """

    detected: bool = False
    data: dict[str, Any] | None = None
    sanitized_text: str | None = None


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
