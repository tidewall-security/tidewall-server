"""Language detector — verifies text is in an allowed language.

Loads ``papluca/xlm-roberta-base-language-detection`` as a HuggingFace
text-classification pipeline. The model emits an ISO 639-1
language code and a confidence score; we mark text as a violation when the
top predicted language is *not* in ``valid_languages``.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import BaseDetector, DetectorResult, FailureCode

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "papluca/xlm-roberta-base-language-detection"


class LanguageDetector(BaseDetector):
    """Detects language violations via a multilingual classifier."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._pipeline = None
        self._valid_languages = config.get("valid_languages", ["en"])
        self._device = config.get("device", "cpu")
        model_path = config.get("model") or _DEFAULT_MODEL
        try:
            from transformers import pipeline

            self._pipeline = pipeline(
                "text-classification",
                model=model_path,
                truncation=True,
                max_length=512,
                device=self._device,
            )
            logger.info("Loaded language classifier: %s", model_path)
        except ImportError:
            logger.warning("transformers not installed — LanguageDetector unavailable")
            self.mark_unavailable(FailureCode.DEPENDENCY_MISSING)
        except Exception:
            logger.warning("Failed to load language classifier %s", model_path, exc_info=True)
            self.mark_unavailable(FailureCode.MODEL_LOAD_FAILED)

    @property
    def name(self) -> str:
        return "language"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        if self._pipeline is None:
            return self.unavailable_result()

        try:
            results = self._pipeline(text)
        except Exception:
            logger.warning("Language classifier inference failed", exc_info=True)
            return DetectorResult.failed(FailureCode.SCAN_FAILED)

        top = results[0] if isinstance(results, list) and results else {}
        predicted = top.get("label", "")
        confidence = max(0.0, min(1.0, float(top.get("score", 0.0))))

        # Violation if the predicted language is not in the allow-list.
        detected = predicted not in self._valid_languages
        if not detected:
            return DetectorResult(detected=False)

        action = "blocked" if self.can_block else "reported"
        languages = [{"language": lang, "confidence": confidence} for lang in self._valid_languages]
        return DetectorResult(
            detected=True,
            data={
                "action": action,
                "languages": languages,
                "predicted": predicted,
            },
        )
