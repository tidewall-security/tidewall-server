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
from typing import Any

from app.services.audit_evidence import report_match as _report_match
from app.services.safe_regex import MAX_MATCHES_PER_SCAN, MAX_PATTERNS, UnsafePatternError, compile_pattern

from .base import BaseDetector, DetectorResult, FailureCode

logger = logging.getLogger(__name__)


class CustomEntityDetector(BaseDetector):
    """Detects custom entities via user-supplied regex patterns."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._patterns: list[Any] = []
        configured = config.get("patterns", []) or []
        if len(configured) > MAX_PATTERNS:
            # Write validation rejects this too, but a policy row can reach the
            # database another way, and N patterns cost N passes over every
            # scanned message however linear each one is. Refusing to enforce
            # is correct here: silently matching the first MAX_PATTERNS would
            # drop rules the administrator wrote, from a detector that redacts.
            logger.error(
                "custom_entity configured with %d patterns, over the %d limit",
                len(configured),
                MAX_PATTERNS,
            )
            self.mark_unavailable(FailureCode.CONFIG_INVALID)
            configured = []
        for raw in configured:
            try:
                # The linear engine, never `re`: these patterns are supplied by
                # an administrator and run against caller-supplied text, which
                # with a backtracking engine is a denial of service waiting to
                # be configured (P0-12).
                self._patterns.append(compile_pattern(raw))
            except UnsafePatternError:
                # A bad pattern is operator error, but skipping it silently
                # removes the rule it expressed — the policy says an entity is
                # detected and it never will be. Validation rejects these at
                # write time; if one reaches here the detector cannot enforce
                # what it was configured to enforce.
                logger.error("Invalid regex pattern in custom_entity policy")
                self.mark_unavailable(FailureCode.CONFIG_INVALID)
        if not self._patterns:
            logger.info("No patterns configured — CustomEntityDetector will be inactive")

    @property
    def name(self) -> str:
        return "custom_entity"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        # A pattern failed to compile, so at least one configured rule cannot
        # be applied. Reporting "nothing found" would claim a clean result from
        # a check that is not running.
        if not self.available:
            return self.unavailable_result()

        if not self._patterns:
            return DetectorResult(detected=False)

        # Collect every match span across all patterns. Each match is a tuple
        # (start, end, value) so we can dedupe overlapping spans cleanly later.
        spans: list[tuple[int, int, str]] = []
        for pattern in self._patterns:
            for match in pattern.finditer(text):
                spans.append((match.start(), match.end(), match.group(0)))
                if len(spans) > MAX_MATCHES_PER_SCAN:
                    # Linear is not free. A legal pattern like `.?` matches once
                    # per character, so retaining every span is its own
                    # exhaustion path. Stopping is necessary — but returning the
                    # spans collected so far would be a partial scan reported as
                    # a complete one, and this detector redacts, so a caller
                    # would receive text it believes was fully sanitised.
                    logger.error(
                        "custom_entity exceeded %d matches in one scan; refusing to report a partial result",
                        MAX_MATCHES_PER_SCAN,
                    )
                    return DetectorResult.failed(FailureCode.SCAN_FAILED)

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
        collector = kwargs.get("matches")
        entities: list[dict[str, Any]] = []
        for n, (start, _end, value) in enumerate(kept, start=1):
            _report_match(collector, self.name, "CUSTOM", value, start, start + len(value))
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
