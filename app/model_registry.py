"""Pinned model artifacts — one source of truth.

Every Hugging Face artifact the product loads is named here with an immutable
commit SHA. Identifiers were previously duplicated across detector modules,
`prewarm.py`, the README and the benchmarks, which is how the prewarm list and
the runtime defaults drifted apart and how a repository that returns 401 stayed
configured long enough to break the Docker build.

Pinning matters beyond availability: an unpinned reference lets an upstream
commit change a model's labels, licence or weights with no change in this
repository. The label mismatch in P0-3 and the identity-label scoring bug in
the toxicity detector were both label problems, and a floating revision can
reintroduce either without warning.

Audit: internal/reviews/2026-08-17-model-reference-audit.md
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelRef:
    """A pinned artifact and what the code expects it to be."""

    repo_id: str
    revision: str
    pipeline_tag: str
    licence: str

    def revision_for(self, model_path: str | None) -> str | None:
        """The pinned revision, but only when loading this exact artifact.

        An operator may configure a different model, and pinning *their* choice
        to *our* SHA would be wrong — it would either fail to resolve or, worse,
        silently fetch an unrelated commit. Returns None in that case, which is
        what `from_pretrained` and `pipeline` expect for "latest".
        """
        return self.revision if model_path == self.repo_id else None


INJECTION = ModelRef(
    repo_id="protectai/deberta-v3-base-prompt-injection-v2",
    revision="90c9989b1a342275dd0d1a95aad283c04e075671",
    pipeline_tag="text-classification",
    licence="apache-2.0",
)

TOXICITY = ModelRef(
    repo_id="unitary/unbiased-toxic-roberta",
    revision="36295dd80b422dc49f40052021430dae76241adc",
    pipeline_tag="text-classification",
    licence="apache-2.0",
)

TOPICS = ModelRef(
    repo_id="MoritzLaurer/roberta-base-zeroshot-v2.0-c",
    revision="d825e740e0c59881cf0b0b1481ccf726b6d65341",
    pipeline_tag="zero-shot-classification",
    licence="mit",
)

LANGUAGE = ModelRef(
    repo_id="papluca/xlm-roberta-base-language-detection",
    revision="9865598389ca9d95637462f743f683b51d75b87b",
    pipeline_tag="text-classification",
    licence="mit",
)

CODE = ModelRef(
    repo_id="philomath-1209/programming-language-identification",
    revision="9090d38e7333a2c6ff00f154ab981a549842c20f",
    pipeline_tag="text-classification",
    licence="wtfpl",
)

# Replaces DunnBC22/codebert-base-Malicious_URLs, which returns 401 anonymously
# — so `RUN python prewarm.py` raised and no Docker image could be built at all.
MALICIOUS_URL = ModelRef(
    repo_id="kmack/malicious-url-detection",
    revision="258499831602e1aea6c1f00e8483b820dd14b391",
    pipeline_tag="text-classification",
    licence="apache-2.0",
)

SENTENCE_SIMILARITY = ModelRef(
    repo_id="sentence-transformers/all-MiniLM-L6-v2",
    revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    pipeline_tag="sentence-similarity",
    licence="apache-2.0",
)

#: Every artifact baked into the image, for prewarm and verification.
ALL: tuple[ModelRef, ...] = (
    INJECTION,
    TOXICITY,
    TOPICS,
    LANGUAGE,
    CODE,
    MALICIOUS_URL,
    SENTENCE_SIMILARITY,
)
