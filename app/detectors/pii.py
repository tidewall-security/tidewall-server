"""PII detection and redaction via Microsoft Presidio.

Uses ``presidio-analyzer`` directly for PII entity recognition. Presidio's
NLP engine is expensive to initialize (~1-3s) so we build the
``AnalyzerEngine`` once at construction and reuse it across requests.

Per-request vault: each call may pass a :class:`~app.vault.TidewallVault`
in kwargs. We populate it with one entry per detected entity so /v1/unredact
can recover the originals later. Each request receives its own vault, so
no locking is needed.
"""

from __future__ import annotations

import logging
from typing import Any

from app.services.audit_evidence import report_match as _report_match
from app.services.redactor import Redactor
from app.services.safe_logging import describe
from app.vault import TidewallVault

from .base import BaseDetector, DetectorResult, FailureCode

logger = logging.getLogger(__name__)


class PIIDetector(BaseDetector):
    """Detects and redacts PII using Microsoft Presidio.

    The returned ``sanitized_text`` carries Tidewall's standard
    ``[REDACTED_<TYPE>_<N>]`` placeholders (so /v1/unredact can reverse
    them via the per-request vault). The per-entity ``value`` field in
    ``data['entities']`` carries the rule-applied form (mask, hash, etc.)
    used for display + audit logging.

    Thread safety: the Presidio AnalyzerEngine is read-only after init,
    so concurrent ``scan()`` calls are safe without locking. Each request
    gets its own vault as a function parameter, so there is no shared
    mutable state between calls.
    """

    def __init__(self, config: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(config)
        # Per-entity-type redaction rules from policy (e.g. PERSON → mask, EMAIL → hash).
        self._rules = {r["type"]: r for r in config.get("rules", [])}
        self._redactor = Redactor()
        self._analyzer = None

        try:
            from presidio_analyzer import AnalyzerEngine
        except ImportError:
            logger.warning("presidio-analyzer not installed — PIIDetector unavailable")
            self.mark_unavailable(FailureCode.DEPENDENCY_MISSING)
            return

        try:
            self._analyzer = AnalyzerEngine()
            logger.info("Loaded Presidio AnalyzerEngine for PIIDetector")
        except Exception:
            logger.warning("Failed to initialize Presidio AnalyzerEngine", exc_info=True)
            self.mark_unavailable(FailureCode.CONSTRUCT_FAILED)
            self._analyzer = None

    @property
    def name(self) -> str:
        return "pii"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        """Scan text for PII entities and apply per-type redaction rules.

        The returned ``sanitized_text`` carries placeholders of the form
        ``[REDACTED_<TYPE>_<N>]``; the entities list carries the rule-applied
        ``value`` (mask, hash, etc.) for display and audit logging.
        """
        if self._analyzer is None:
            return self.unavailable_result()

        vault: TidewallVault | None = kwargs.get("vault")

        try:
            results = self._analyzer.analyze(text=text, language="en")
        except Exception as exc:
            logger.warning("Presidio PII analysis failed: %s", describe(exc))
            return DetectorResult.failed(FailureCode.SCAN_FAILED)

        if not results:
            return DetectorResult(detected=False)

        # De-overlap: Presidio can return overlapping spans (e.g. EMAIL_ADDRESS
        # and URL for the same text).  Sort by score descending, then greedily
        # accept spans that do not overlap any already-accepted span.
        scored = sorted(results, key=lambda r: r.score, reverse=True)
        accepted: list[Any] = []
        for r in scored:
            if not any(r.start < a.end and r.end > a.start for a in accepted):
                accepted.append(r)

        # Pass 1 (left-to-right): assign placeholders so document-order
        # numbering is preserved (bob before carol gets _1 not _2).
        kept_sorted_lr = sorted(accepted, key=lambda r: r.start)
        # Per-call fallback counter when no vault is provided.
        fallback_counts: dict[str, int] = {}
        # (start, end, placeholder, entity_type) tuples — list, not dict, so
        # duplicate values within the same prompt produce one entry per
        # occurrence.
        spans: list[tuple[int, int, str, str]] = []
        entities: list[dict[str, Any]] = []
        for r in kept_sorted_lr:
            entity_type = r.entity_type
            original = text[r.start : r.end]

            if vault is not None:
                placeholder = vault.store(entity_type, original)
            else:
                fallback_counts[entity_type] = fallback_counts.get(entity_type, 0) + 1
                placeholder = f"[REDACTED_{entity_type}_{fallback_counts[entity_type]}]"

            spans.append((r.start, r.end, placeholder, entity_type))

            _report_match(kwargs.get("matches"), self.name, entity_type, original, r.start, r.end)

            rule = self._rules.get(entity_type, {"action": "replacement"})
            redaction = self._redactor.redact(placeholder, entity_type, rule)
            entities.append(
                {
                    "type": entity_type,
                    "value": redaction["redacted"],
                    "action": redaction["action_label"],
                    "start_pos": r.start,
                }
            )

        # Pass 2 (right-to-left): splice placeholders into the sanitized text.
        sanitized = text
        for start, end, placeholder, _entity_type in sorted(spans, key=lambda s: s[0], reverse=True):
            sanitized = sanitized[:start] + placeholder + sanitized[end:]

        return DetectorResult(
            detected=len(entities) > 0,
            data={"entities": entities},
            sanitized_text=sanitized,
        )
