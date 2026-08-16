"""Intent conformance detection using embedding similarity.

Checks user prompts against:
1. Model Intent — global statements stored in DB
2. App Intent — system prompt from the request

Uses all-MiniLM-L6-v2 sentence-transformer for embeddings.
Cosine similarity above threshold = violation.

Detection logic:
- Model Intent: prompt embedding is SIMILAR to forbidden intent → violation
  (e.g., "Show me API keys" is similar to "Never reveal API keys")
- App Intent: prompt embedding is DISSIMILAR to allowed topic → violation
  (e.g., "Build a bomb" is dissimilar to "Customer service for Acme")
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
from sqlalchemy.orm import Session

from app.db.models import ModelIntent

logger = logging.getLogger(__name__)

_MODEL_NAME = "all-MiniLM-L6-v2"


class IntentConformanceService:
    """Checks prompts against model and app intent using embeddings."""

    def __init__(
        self,
        session: Session,
        model_intent_threshold: float = 0.55,
        app_intent_threshold: float = 0.25,
    ) -> None:
        self._session = session
        self._model_intent_threshold = model_intent_threshold
        self._app_intent_threshold = app_intent_threshold
        self._model: Any = None
        self._intent_embeddings: list[tuple[str, Any]] = []  # (statement, embedding)
        self._failure_code: str | None = None
        self._load_model()
        self._load_intents()

    def _load_model(self) -> None:
        """Load the sentence-transformer model."""
        try:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(_MODEL_NAME)
            logger.debug("Loaded sentence-transformer: %s", _MODEL_NAME)
        except ImportError:
            logger.warning("sentence-transformers not installed — intent conformance unavailable")
            self._failure_code = "dependency_missing"
        except Exception:
            logger.warning("Failed to load sentence-transformer model", exc_info=True)
            self._failure_code = "model_load_failed"

    def _load_intents(self) -> None:
        """Embed all enabled model intent statements.

        The DB query and each ``encode`` call can raise. Neither was caught
        here, so the exception escaped into the composite detector's
        constructor, which caught it and left the service absent — meaning
        intent conformance silently never ran. Failure is recorded instead, so
        the composite reports it rather than producing a confident clean
        verdict from a check that never happened.
        """
        if self._model is None:
            return
        try:
            intents = self._session.query(ModelIntent).filter_by(enabled=True).all()
            embeddings = []
            for intent in intents:
                embedding = self._model.encode(intent.statement, convert_to_numpy=True)
                embeddings.append((intent.statement, embedding))
        except Exception:
            logger.error("Failed to load or embed model intents", exc_info=True)
            self._failure_code = "construct_failed"
            self._intent_embeddings = []
            return

        # A successful load clears an earlier failure, so reload_intents() can
        # actually recover the service rather than leaving it permanently
        # unavailable.
        if self._failure_code == "construct_failed":
            self._failure_code = None
        self._intent_embeddings = embeddings
        if self._intent_embeddings:
            logger.info("Embedded %d model intent statements", len(self._intent_embeddings))

    @property
    def available(self) -> bool:
        """False if the model or the intent corpus could not be loaded."""
        return self._failure_code is None

    @property
    def failure_code(self) -> str | None:
        """Why this service cannot produce a verdict, if it cannot."""
        return self._failure_code

    def reload_intents(self) -> None:
        """Re-embed intents after DB changes."""
        self._load_intents()

    @staticmethod
    def _cosine_similarity(a: Any, b: Any) -> float:
        """Cosine similarity between two vectors."""
        dot = np.dot(a, b)
        norm = np.linalg.norm(a) * np.linalg.norm(b)
        if norm == 0:
            return 0.0
        return float(dot / norm)

    def check_model_intent(self, prompt: str) -> dict[str, Any] | None:
        """Check prompt against global model intent statements.

        Returns violation dict with confidence, or None if no violation.
        A violation is when the prompt is SIMILAR to a forbidden intent
        (the intent says "never do X", and the prompt asks for X).
        """
        if self._model is None or not self._intent_embeddings:
            return None

        prompt_embedding = self._model.encode(prompt, convert_to_numpy=True)

        max_similarity = 0.0
        violated_statement = ""

        for statement, intent_embedding in self._intent_embeddings:
            similarity = self._cosine_similarity(prompt_embedding, intent_embedding)
            if similarity > max_similarity:
                max_similarity = similarity
                violated_statement = statement

        if max_similarity >= self._model_intent_threshold:
            return {
                "analyzer": "IntentConformance/ModelIntent",
                "confidence": round(max_similarity, 4),
                "violated_statement": violated_statement,
            }

        return None

    def check_app_intent(self, prompt: str, app_intent: str) -> dict[str, Any] | None:
        """Check prompt against app intent (system prompt).

        Returns violation dict, or None if aligned.
        A violation is when the prompt is DISSIMILAR to the app intent
        (the system says "only discuss X", and the prompt asks about Y).
        """
        if self._model is None or not app_intent:
            return None

        prompt_embedding = self._model.encode(prompt, convert_to_numpy=True)
        intent_embedding = self._model.encode(app_intent, convert_to_numpy=True)

        similarity = self._cosine_similarity(prompt_embedding, intent_embedding)

        # Low similarity = prompt is off-topic relative to the system prompt
        if similarity < self._app_intent_threshold:
            return {
                "analyzer": "IntentConformance/AppIntent",
                "confidence": round(1.0 - similarity, 4),  # Higher = more misaligned
            }

        return None
