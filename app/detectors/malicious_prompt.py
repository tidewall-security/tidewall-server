"""Composite Malicious Prompt Detector.

Matches an industry structure with independent sub-detectors:
1. Custom Malicious List (override → detected)
2. Custom Benign List (override → not detected)
3. Generic Injection/Jailbreak (HF text-classification model)
4. Intent Conformance (sentence-transformer cosine similarity)

Evaluation order: malicious list → benign list → ML → intent
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseDetector, DetectorResult

logger = logging.getLogger(__name__)


class MaliciousPromptDetector(BaseDetector):
    """Composite prompt injection detector with sub-toggles.

    Supports four independent detection paths, configured via policy YAML:

    1. **Custom malicious/benign lists** — exact/substring/regex matching
       against admin-curated prompt lists stored in the DB.  These act as
       hard overrides: a malicious match short-circuits to "detected",
       a benign match short-circuits to "not detected".

    2. **ML-based injection detection** — a text-classification model that
       scores prompts for injection/jailbreak probability.  Requires both
       ``model`` and ``tokenizer`` keys in the policy YAML.

    3. **Intent conformance** — checks whether the user prompt aligns with
       declared model/app intent statements stored in the DB.  Uses
       sentence-transformer cosine similarity.
    """

    def __init__(self, config: dict[str, Any], session_factory: Any = None) -> None:
        """Initialize all sub-detectors based on policy config.

        The ML model is loaded once here and reused across requests.
        This is the most expensive part of startup (~2-5s per model).
        """
        super().__init__(config)

        # Sub-detector toggles — each can be independently enabled in policy YAML
        self._generic_injection_enabled = config.get("generic_injection_detection", True)
        self._custom_malicious_enabled = config.get("custom_malicious_detection", False)
        self._custom_benign_enabled = config.get("custom_benign_detection", False)

        # ML model state — direct HuggingFace pipeline only.
        # Configure the model with both ``model`` and ``tokenizer`` keys in
        # policy YAML so the loader has everything it needs.
        self._pipeline = None
        self._injection_label = config.get("injection_label")  # label to treat as "injection" (e.g. 1, "LABEL_1")
        self._threshold = config.get("threshold", 0.9)  # score above this = injection
        if self._generic_injection_enabled:
            tokenizer_path = config.get("tokenizer")
            model_path = config.get("model")
            if tokenizer_path and model_path:
                try:
                    from transformers import (
                        AutoModelForSequenceClassification,
                        AutoTokenizer,
                        pipeline,
                    )

                    tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)
                    model = AutoModelForSequenceClassification.from_pretrained(model_path)
                    self._pipeline = pipeline(
                        "text-classification",
                        model=model,
                        tokenizer=tokenizer,
                        truncation=True,
                        max_length=512,
                        device="cpu",
                    )
                    logger.info("Loaded direct HF pipeline: model=%s tokenizer=%s", model_path, tokenizer_path)
                except Exception:
                    logger.warning("Failed to load direct HF pipeline for %s", model_path, exc_info=True)
            else:
                # No usable model configured — generic-injection detection is off.
                logger.info(
                    "malicious_prompt.generic_injection_detection enabled but no "
                    "model+tokenizer pair configured; ML detection disabled"
                )

        self._prompt_list_svc = None
        if (self._custom_malicious_enabled or self._custom_benign_enabled) and session_factory:
            try:
                from app.services.prompt_list_service import PromptListService

                self._prompt_list_svc = PromptListService(session_factory())
            except Exception:
                logger.warning("Failed to initialize PromptListService")

        intent_config = config.get("intent_conformance", {})
        if isinstance(intent_config, dict):
            self._intent_enabled = intent_config.get("enabled", False)
            self._check_model_intent = intent_config.get("check_model_intent", True)
            self._check_app_intent = intent_config.get("check_app_intent", True)
            self._intent_threshold = intent_config.get("threshold", 0.3)
        else:
            self._intent_enabled = False
            self._check_model_intent = False
            self._check_app_intent = False
            self._intent_threshold = 0.3

        self._intent_svc = None
        if self._intent_enabled and session_factory:
            try:
                from app.services.intent_conformance_service import IntentConformanceService

                self._intent_svc = IntentConformanceService(
                    session_factory(),
                    model_intent_threshold=self._intent_threshold,
                    app_intent_threshold=self._intent_threshold,
                )
            except Exception:
                logger.warning("Failed to initialize IntentConformanceService", exc_info=True)

    @property
    def name(self) -> str:
        return "malicious_prompt"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        """Evaluate text through the 4-step detection pipeline.

        Returns as soon as any step produces a definitive result (short-circuit).
        Steps 1-2 (custom lists) are O(n) string matching — fast.
        Step 3 (ML model) is the expensive inference call.
        Step 4 (intent conformance) uses sentence-transformer similarity.
        """
        analyzer_responses: list[dict[str, Any]] = []

        # 1. Custom malicious list — override to detected
        if self._custom_malicious_enabled and self._prompt_list_svc:
            if self._prompt_list_svc.check_match(text, "malicious"):
                analyzer_responses.append({"analyzer": "CustomMaliciousList", "confidence": 1.0})
                action = "blocked" if self.can_block else "reported"
                return DetectorResult(
                    detected=True,
                    data={"action": action, "analyzer_responses": analyzer_responses},
                )

        # 2. Custom benign list — override to not detected
        if self._custom_benign_enabled and self._prompt_list_svc:
            if self._prompt_list_svc.check_match(text, "benign"):
                return DetectorResult(detected=False)

        # 3. Generic injection ML model — direct HF pipeline only.
        if self._generic_injection_enabled and self._pipeline:
            results = self._pipeline(text)
            injection_score = 0.0
            for r in results:
                if r["label"] == self._injection_label:
                    injection_score = r["score"]
                    break
            is_valid = injection_score < self._threshold
            score = injection_score
            analyzer_name = self.config.get("model", "direct-hf-pipeline")

            clamped = max(0.0, min(1.0, score))
            analyzer_responses.append(
                {
                    "analyzer": analyzer_name,
                    "confidence": clamped,
                }
            )
            if not is_valid:
                action = "blocked" if self.can_block else "reported"
                return DetectorResult(
                    detected=True,
                    data={"action": action, "analyzer_responses": analyzer_responses},
                )

        # 4. Intent conformance
        if self._intent_enabled and self._intent_svc:
            if self._check_model_intent:
                violation = self._intent_svc.check_model_intent(text)
                if violation:
                    analyzer_responses.append(violation)
            if self._check_app_intent:
                messages = kwargs.get("messages", [])
                app_intent = None
                for msg in messages:
                    if isinstance(msg, dict) and msg.get("role") == "system":
                        app_intent = msg.get("content", "")
                        break
                if app_intent:
                    violation = self._intent_svc.check_app_intent(text, app_intent)
                    if violation:
                        analyzer_responses.append(violation)

        # Check if intent conformance found violations (steps 1-3 didn't trigger)
        if analyzer_responses and any("IntentConformance" in r.get("analyzer", "") for r in analyzer_responses):
            action = "blocked" if self.can_block else "reported"
            return DetectorResult(
                detected=True,
                data={"action": action, "analyzer_responses": analyzer_responses},
            )

        # Not detected
        return DetectorResult(
            detected=False,
            data={"action": "reported", "analyzer_responses": analyzer_responses} if analyzer_responses else None,
        )
