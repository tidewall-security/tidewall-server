"""Pre-warm every pinned model artifact at Docker build time.

Downloads each artifact into the image so a running container never fetches a
model on the request path.

Driven entirely by :mod:`app.model_registry`. It previously repeated the
identifiers itself, which let it drift from the runtime defaults — and one of
those repeated identifiers,`DunnBC22/codebert-base-Malicious_URLs`, returns 401
anonymously. Because nothing caught the exception, the RUN layer raised and no
image could be built at all.

Failures are now collected and reported together rather than aborting on the
first one, so a broken reference names itself instead of hiding whatever comes
after it. The exit code is still non-zero: a half-populated image would fail
later, at runtime, on a user's request.
"""

from __future__ import annotations

import logging
import sys

from app.model_registry import (
    ALL,
    CODE,
    INJECTION,
    LANGUAGE,
    MALICIOUS_URL,
    SENTENCE_SIMILARITY,
    TOPICS,
    TOXICITY,
    ModelRef,
)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("prewarm")


def _fetch(ref: ModelRef) -> None:
    """Materialise one artifact using the loader the application will use."""
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

    if ref is SENTENCE_SIMILARITY:
        from sentence_transformers import SentenceTransformer

        SentenceTransformer(ref.repo_id, revision=ref.revision)
    elif ref is TOPICS:
        pipeline("zero-shot-classification", model=ref.repo_id, device="cpu", revision=ref.revision)
    elif ref is TOXICITY:
        pipeline("text-classification", model=ref.repo_id, top_k=None, device="cpu", revision=ref.revision)
    elif ref in (INJECTION, LANGUAGE, CODE, MALICIOUS_URL):
        AutoTokenizer.from_pretrained(ref.repo_id, revision=ref.revision)
        AutoModelForSequenceClassification.from_pretrained(ref.repo_id, revision=ref.revision)
    else:  # pragma: no cover - a new entry with no fetch strategy
        raise RuntimeError(f"no prewarm strategy for {ref.repo_id}")


def main() -> int:
    logger.info("Pre-warming %d pinned model artifacts...", len(ALL))
    failures: list[tuple[str, str]] = []

    for ref in ALL:
        logger.info("  %s @ %s", ref.repo_id, ref.revision[:12])
        try:
            _fetch(ref)
        except Exception as exc:  # noqa: BLE001 - reported, then re-raised in aggregate
            logger.error("    FAILED: %s", exc)
            failures.append((ref.repo_id, str(exc)))

    # Presidio's engine and its spaCy backbone.
    try:
        from presidio_analyzer import AnalyzerEngine

        AnalyzerEngine()
        logger.info("  Presidio analyzer engine")
    except Exception as exc:  # noqa: BLE001
        logger.error("    FAILED: Presidio — %s", exc)
        failures.append(("presidio", str(exc)))

    if failures:
        logger.error("")
        logger.error("%d artifact(s) could not be fetched:", len(failures))
        for repo_id, err in failures:
            logger.error("  %s: %s", repo_id, err)
        logger.error("")
        logger.error("Every artifact must be fetchable anonymously at its pinned revision.")
        return 1

    logger.info("All %d artifacts pre-warmed.", len(ALL))
    return 0


if __name__ == "__main__":
    sys.exit(main())
