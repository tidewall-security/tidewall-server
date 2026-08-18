"""Malicious entity detector — IPs, URLs, domains.

Uses entity extraction + threat intel (local blocklists, ML, external APIs)
with per-entity-type action rules matching an industry model.
"""

from __future__ import annotations

import logging
from typing import Any

from app.model_registry import MALICIOUS_URL as _URL_REF
from app.services.safe_logging import describe

from .base import BaseDetector, DetectorResult, FailureCode

logger = logging.getLogger(__name__)


class MaliciousEntityDetector(BaseDetector):
    """Detects malicious IPs, URLs, and domains with per-type actions."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)

        # Per-type rules: {type: {action: defang/block/report/disabled}}
        self._rules: dict[str, dict[str, Any]] = {}
        for rule in config.get("rules", []):
            self._rules[rule["type"]] = rule

        # Threat intel service
        intel_config = config.get("intel", {})
        from app.services.threat_intel_service import ThreatIntelService

        self._threat_intel = ThreatIntelService(intel_config)

        # ML URL classifier — direct HF pipeline.
        # Threshold for the ML URL classifier (separate from threat-intel logic).
        self._ml_threshold = config.get("threshold", 0.5)
        self._ml_pipeline = None
        if intel_config.get("ml_url_classification", True):
            model_path = config.get("url_model") or _URL_REF.repo_id
            device = config.get("device", "cpu")
            try:
                from transformers import pipeline

                self._ml_pipeline = pipeline(
                    "text-classification",
                    model=model_path,
                    revision=_URL_REF.revision_for(model_path),
                    truncation=True,
                    max_length=512,
                    device=device,
                )
                logger.info("Loaded malicious-URL classifier: %s", model_path)
            except ImportError:
                logger.warning("transformers not installed — ML URL classification unavailable")
                self.mark_unavailable(FailureCode.DEPENDENCY_MISSING)
            except Exception:
                logger.warning("Failed to load malicious-URL classifier %s", model_path, exc_info=True)
                self.mark_unavailable(FailureCode.MODEL_LOAD_FAILED)

        # Redactor for defanging
        from app.services.redactor import Redactor

        self._redactor = Redactor()

    @property
    def name(self) -> str:
        return "malicious_entity"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        from app.services.entity_extractor import extract_entities

        # The configured URL classifier failed to load, so URL classification
        # cannot run. Returning a confident clean verdict here — which is what
        # happened before — reports "no malicious entities" from a detector
        # with no way to find one.
        if not self.available:
            return self.unavailable_result()

        # Extract all entities from text
        extracted = extract_entities(text)
        if not extracted:
            return DetectorResult(detected=False)

        # Check each entity against threat intel + apply per-type rules
        malicious_entities: list[dict[str, Any]] = []
        sanitized = text

        for entity in extracted:
            etype = entity["type"]
            value = entity["value"]
            start_pos = entity["start_pos"]

            # Get per-type rule (default to report)
            rule = self._rules.get(etype, {"action": "report"})
            action = rule.get("action", "report")

            if action == "disabled":
                continue

            # Check if malicious via threat intel
            is_malicious = self._threat_intel.is_malicious(value, etype)

            # Also check via ML for URLs (direct HF pipeline)
            if not is_malicious and etype == "URL" and self._ml_pipeline:
                try:
                    results = self._ml_pipeline(value)
                    top = results[0] if isinstance(results, list) and results else {}
                    label = str(top.get("label", "")).lower()
                    score = float(top.get("score", 0.0))
                    # Model emits "LABEL_1" or "malicious" for the positive class
                    # and "LABEL_0"/"benign" for negative; flag anything else
                    # above the configured threshold.
                    if label not in {"benign", "label_0"} and score >= self._ml_threshold:
                        is_malicious = True
                except Exception as exc:
                    # Do not log `value`: URLs carry credentials and query
                    # tokens. The failure is attributable without the payload.
                    logger.warning("ML URL classifier failed: %s", describe(exc))
                    return DetectorResult.failed(FailureCode.SCAN_FAILED)

            if not is_malicious:
                continue

            # Apply action
            if action == "defang":
                redaction = self._redactor.redact(value, etype, {"action": "defang"})
                display_value = redaction["redacted"]
                action_label = "defanged"
                # Replace in sanitized text
                sanitized = sanitized.replace(value, display_value, 1)
            elif action == "block":
                display_value = value
                action_label = "blocked"
            else:  # report
                display_value = value
                action_label = "reported"

            malicious_entities.append(
                {
                    "type": etype,
                    "value": display_value,
                    "action": action_label,
                    "start_pos": start_pos,
                    "raw": value,
                }
            )

        if not malicious_entities:
            return DetectorResult(detected=False)

        # If any entity was blocked, the detector blocks
        any_defanged = any(e["action"] == "defanged" for e in malicious_entities)

        return DetectorResult(
            detected=True,
            data={"entities": malicious_entities},
            sanitized_text=sanitized if any_defanged else None,
        )
