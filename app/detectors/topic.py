"""Topic + toxicity detector — combines two independent HF pipelines.

- **BanTopics** — ``MoritzLaurer/roberta-base-zeroshot-v2.0-c`` as a
  ``zero-shot-classification`` pipeline. The configured ``topics`` list
  is passed in as candidate labels; if the top label's score exceeds
  ``threshold``, we flag the topic.

- **Toxicity** — ``unitary/unbiased-toxic-roberta`` as a multi-label
  ``text-classification`` pipeline. The model emits scores per toxicity
  axis (toxic, severe_toxic, obscene, threat, insult, identity_hate);
  we take the max and flag when it exceeds ``toxicity_threshold``.

Both sub-detectors are independent — either may be configured without
the other.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseDetector, DetectorResult

logger = logging.getLogger(__name__)

_DEFAULT_TOPICS_MODEL = "MoritzLaurer/roberta-base-zeroshot-v2.0-c"
_DEFAULT_TOXICITY_MODEL = "unitary/unbiased-toxic-roberta"


class TopicDetector(BaseDetector):
    """Detects banned topics + general toxicity via two HF pipelines."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._topics_pipeline = None
        self._toxicity_pipeline = None
        self._topics: list[str] = config.get("topics", []) or []
        self._topic_threshold = config.get("threshold", 0.75)
        self._toxicity_threshold = config.get("toxicity_threshold", 0.5)
        self._device = config.get("device", "cpu")

        try:
            from transformers import pipeline
        except ImportError:
            logger.warning("transformers not installed — TopicDetector disabled")
            return

        if self._topics:
            topics_model = config.get("topics_model") or _DEFAULT_TOPICS_MODEL
            try:
                self._topics_pipeline = pipeline(
                    "zero-shot-classification",
                    model=topics_model,
                    device=self._device,
                )
                logger.info("Loaded topics classifier: %s", topics_model)
            except Exception:
                logger.warning("Failed to load topics model %s", topics_model, exc_info=True)

        toxicity_model = config.get("toxicity_model") or _DEFAULT_TOXICITY_MODEL
        try:
            self._toxicity_pipeline = pipeline(
                "text-classification",
                model=toxicity_model,
                top_k=None,  # return all labels with scores (multi-label)
                truncation=True,
                max_length=512,
                device=self._device,
            )
            logger.info("Loaded toxicity classifier: %s", toxicity_model)
        except Exception:
            logger.warning("Failed to load toxicity model %s", toxicity_model, exc_info=True)

    @property
    def name(self) -> str:
        return "topic"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        if self._topics_pipeline is None and self._toxicity_pipeline is None:
            return DetectorResult(detected=False)

        topics_found: list[dict[str, Any]] = []
        detected = False

        # Toxicity: take the max score across all toxicity sub-labels.
        if self._toxicity_pipeline is not None:
            try:
                results = self._toxicity_pipeline(text)
                # top_k=None returns [[{label, score}, ...]] for a single input.
                scores = (
                    results[0] if isinstance(results, list) and results and isinstance(results[0], list) else results
                )
                tox_score = max((float(r["score"]) for r in scores), default=0.0)
                if tox_score >= self._toxicity_threshold:
                    detected = True
                    topics_found.append({"topic": "toxicity", "confidence": max(0.0, min(1.0, tox_score))})
            except Exception:
                logger.warning("Toxicity classifier inference failed", exc_info=True)

        # Banned topics: zero-shot classification against the candidate list.
        if self._topics_pipeline is not None and self._topics:
            try:
                zsl = self._topics_pipeline(text, candidate_labels=self._topics, multi_label=True)
                # Returns {labels: [...], scores: [...]} sorted by score desc.
                top_label = zsl["labels"][0] if zsl.get("labels") else None
                top_score = float(zsl["scores"][0]) if zsl.get("scores") else 0.0
                if top_label and top_score >= self._topic_threshold:
                    detected = True
                    topics_found.append({"topic": top_label, "confidence": max(0.0, min(1.0, top_score))})
            except Exception:
                logger.warning("Topics classifier inference failed", exc_info=True)

        if not detected:
            return DetectorResult(detected=False)

        action = "blocked" if self.can_block else "reported"
        return DetectorResult(
            detected=True,
            data={
                "action": action,
                "topics": topics_found,
            },
        )
