"""Custom-entity detector — matches user-supplied regex patterns.

Each match is replaced with a placeholder of the form ``[REDACTED_CUSTOM_<N>]``
where ``<N>`` is a 1-based counter that resets each call to ``scan()``,
consistent with the placeholder convention used by the PII and secrets
detectors.

If no patterns are configured, the detector reports inactive — calling
``scan()`` is a no-op so policies that don't enable ``custom_entity``
pay no cost beyond a dict lookup.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .base import BaseDetector, DetectorResult

logger = logging.getLogger(__name__)


class CustomEntityDetector(BaseDetector):
    """Detects custom entities via user-supplied regex patterns."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._patterns: list[re.Pattern[str]] = []
        for raw in config.get("patterns", []) or []:
            try:
                self._patterns.append(re.compile(raw))
            except re.error:
                # A bad pattern in policy config is operator error; log it
                # and skip so the rest of the patterns still work.
                logger.warning("Invalid regex pattern: %s", raw)
        if not self._patterns:
            logger.info("No patterns configured — CustomEntityDetector will be inactive")

    @property
    def name(self) -> str:
        return "custom_entity"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        if not self._patterns:
            return DetectorResult(detected=False)

        # Collect every match span across all patterns. Each match is a tuple
        # (start, end, value) so we can dedupe overlapping spans cleanly later.
        spans: list[tuple[int, int, str]] = []
        for pattern in self._patterns:
            for match in pattern.finditer(text):
                spans.append((match.start(), match.end(), match.group(0)))

        if not spans:
            return DetectorResult(detected=False)

        # Sort leftmost-first; ties broken by longest span first so a wider
        # pattern wins over a narrower one starting at the same position.
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))

        # Drop any span whose start falls inside the previously-kept span.
        # This protects against destructive mutations when two patterns produce
        # overlapping matches (e.g. r"foo" and r"foo.*bar" both match "foobar").
        kept: list[tuple[int, int, str]] = []
        last_end = -1
        for start, end, value in spans:
            if start < last_end:
                continue
            kept.append((start, end, value))
            last_end = end

        # Build entities (left-to-right) and sanitize text (right-to-left so
        # earlier offsets stay valid as we splice). Note: entity ``start_pos``
        # records the position in the ORIGINAL ``text``, not in ``sanitized``.
        entities: list[dict[str, Any]] = []
        for n, (start, _end, value) in enumerate(kept, start=1):
            placeholder = f"[REDACTED_CUSTOM_{n}]"
            entities.append(
                {
                    "type": "CUSTOM",
                    "value": value,
                    # custom_entity always replaces; per-rule actions like
                    # mask/hash are intentionally not honored for this detector.
                    "action": "redacted:replaced",
                    "start_pos": start,
                    "placeholder": placeholder,
                }
            )

        sanitized = text
        for n, (start, end, _value) in reversed(list(enumerate(kept, start=1))):
            placeholder = f"[REDACTED_CUSTOM_{n}]"
            sanitized = sanitized[:start] + placeholder + sanitized[end:]

        # Drop the internal `placeholder` key from entities before returning —
        # it was only carried for the right-to-left mutation pass above.
        for entity in entities:
            entity.pop("placeholder", None)

        return DetectorResult(
            detected=True,
            data={"entities": entities},
            sanitized_text=sanitized,
        )
