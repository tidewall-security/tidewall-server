"""Competitor-mention detector.

Uses Presidio Analyzer with two layers:

1. A :class:`PatternRecognizer` containing a deny-list of competitor
   names — catches exact / case-insensitive substring matches reliably,
   even for names the underlying NER doesn't recognize as organizations.
2. The default Presidio ``ORGANIZATION`` recognizer — catches mentions
   phrased as "Acme Corp" / "Acme Inc." style entities that survived
   step 1.

A name passed in via config matches if step 1 fires *or* if step 2 fires
and the recognized text equals a configured competitor (case-insensitive).
(For embedded mentions like "Acme Corp" where "Acme" is the competitor,
the deny-list layer in step 1 catches the bare "Acme" inside the span.)
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseDetector, DetectorResult, FailureCode

logger = logging.getLogger(__name__)


class CompetitorsDetector(BaseDetector):
    """Detects mentions of configured competitor names."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._competitors: list[str] = config.get("competitors", []) or []
        self._analyzer = None
        if not self._competitors:
            logger.info("No competitors configured — CompetitorsDetector inactive")
            return

        try:
            from presidio_analyzer import AnalyzerEngine, PatternRecognizer
        except ImportError:
            logger.warning("presidio-analyzer not installed — CompetitorsDetector unavailable")
            self.mark_unavailable(FailureCode.DEPENDENCY_MISSING)
            return

        try:
            self._analyzer = AnalyzerEngine()
            # Custom recognizer keyed off the configured competitor names.
            # ``deny_list`` does case-insensitive whole-word matching internally.
            recognizer = PatternRecognizer(
                supported_entity="COMPETITOR",
                deny_list=self._competitors,
            )
            self._analyzer.registry.add_recognizer(recognizer)
            logger.info("Loaded Presidio competitor recognizer with %d names", len(self._competitors))
        except Exception:
            logger.warning("Failed to initialize Presidio for competitors", exc_info=True)
            self.mark_unavailable(FailureCode.CONSTRUCT_FAILED)
            self._analyzer = None

    @property
    def name(self) -> str:
        return "competitors"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        # An empty competitor list is a deliberately inactive detector, not a
        # broken one: there is nothing to look for, so "found nothing" is the
        # honest and complete answer. Conflating it with a failed analyzer made
        # an intentionally empty config degrade every request — and block every
        # request under on_detector_failure=block.
        if not self._competitors:
            return DetectorResult(detected=False)

        if self._analyzer is None:
            return self.unavailable_result()

        try:
            results = self._analyzer.analyze(
                text=text,
                entities=["COMPETITOR", "ORGANIZATION"],
                language="en",
            )
        except Exception:
            logger.warning("Competitors analyzer inference failed", exc_info=True)
            return DetectorResult.failed(FailureCode.SCAN_FAILED)

        found: list[str] = []
        lowered_competitors = {c.lower() for c in self._competitors}
        for r in results:
            span_text = text[r.start : r.end]
            if r.entity_type == "COMPETITOR":
                found.append(span_text)
            elif span_text.lower() in lowered_competitors:
                # ORGANIZATION span happened to match a configured competitor.
                found.append(span_text)

        # De-dupe while preserving discovery order.
        seen: set[str] = set()
        unique: list[str] = []
        for x in found:
            if x not in seen:
                seen.add(x)
                unique.append(x)

        if not unique:
            return DetectorResult(detected=False)

        action = "blocked" if self.can_block else "reported"
        return DetectorResult(
            detected=True,
            data={
                "action": action,
                "entities": unique,
            },
        )
