"""Code-snippet detector — flags text containing programming-language code.

Loads a HuggingFace text-classification pipeline. The model returns a single
label (the predicted language) and a score; we treat the text as containing
code if the predicted language is in the allow-list of ``languages`` and the
score exceeds ``threshold``.

The default model is ``philomath-1209/programming-language-identification``.
Override via ``model`` in detector config.
"""

from __future__ import annotations

import logging
from typing import Any

from app.model_registry import CODE as _REF

from .base import BaseDetector, DetectorResult, FailureCode

logger = logging.getLogger(__name__)


_DEFAULT_MODEL = _REF.repo_id


class CodeDetector(BaseDetector):
    """Detects code snippets via a programming-language classifier."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._pipeline = None
        self._languages = config.get("languages", ["Python"])
        self._threshold = config.get("threshold", 0.5)
        self._device = config.get("device", "cpu")
        model_path = config.get("model") or _DEFAULT_MODEL
        try:
            from transformers import pipeline

            self._pipeline = pipeline(
                "text-classification",
                model=model_path,
                revision=_REF.revision_for(model_path),
                truncation=True,
                max_length=512,
                device=self._device,
            )
            logger.info("Loaded code-language classifier: %s", model_path)
        except ImportError:
            logger.warning("transformers not installed — CodeDetector unavailable")
            self.mark_unavailable(FailureCode.DEPENDENCY_MISSING)
        except Exception:
            logger.warning("Failed to load code classifier %s", model_path, exc_info=True)
            self.mark_unavailable(FailureCode.MODEL_LOAD_FAILED)

    @property
    def name(self) -> str:
        return "code"

    def scan(self, text: str, **kwargs: Any) -> DetectorResult:
        if self._pipeline is None:
            return self.unavailable_result()

        try:
            results = self._pipeline(text)
        except Exception:
            logger.warning("Code classifier inference failed", exc_info=True)
            return DetectorResult.failed(FailureCode.SCAN_FAILED)

        # Pipeline returns [{"label": "Python", "score": 0.93}] for single inputs.
        top = results[0] if isinstance(results, list) and results else {}
        label = top.get("label", "Unknown")
        score = float(top.get("score", 0.0))

        # Detected if the top language is in the configured allow-list and
        # the model is reasonably confident about it.
        detected = label in self._languages and score >= self._threshold

        if not detected:
            return DetectorResult(detected=False)

        action = "blocked" if self.can_block else "reported"
        return DetectorResult(
            detected=True,
            data={
                "action": action,
                "language": label,
            },
        )
