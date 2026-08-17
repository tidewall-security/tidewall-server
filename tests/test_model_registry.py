"""Every pinned artifact must be fetchable, ungated, and what the code expects.

Two model references were found broken by accident rather than by a test: the
injection model was `gated: manual`, so a clean build silently had no detector;
and the URL classifier returned 401, which made `RUN python prewarm.py` raise
and produced no Docker image at all.

An audit then found the wider pattern — eight artifacts, one pinned. These
tests are the control. The offline ones run everywhere; the network one is
marked so it can run on a schedule rather than every commit.

Audit: internal/reviews/2026-08-17-model-reference-audit.md
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import pytest

from app.model_registry import ALL, ModelRef

_HF_API = "https://huggingface.co/api/models/{repo_id}"
_HF_FILE = "https://huggingface.co/{repo_id}/resolve/{revision}/config.json"

# Opt-in: these make real network calls. Run with TIDEWALL_CHECK_MODELS=1,
# or on a schedule in CI.
_NETWORK = pytest.mark.skipif(
    os.environ.get("TIDEWALL_CHECK_MODELS") != "1",
    reason="set TIDEWALL_CHECK_MODELS=1 to verify model references against Hugging Face",
)


# ---------------------------------------------------------------------------
# Offline — always run
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ref", ALL, ids=lambda r: r.repo_id)
def test_every_reference_is_pinned_to_a_commit_sha(ref: ModelRef):
    """A branch name lets upstream change labels, licence or weights silently.

    Both label defects this codebase has had would be reintroducible by an
    unpinned reference.
    """
    assert len(ref.revision) == 40, f"{ref.repo_id} is not pinned to a 40-char commit SHA"
    assert all(c in "0123456789abcdef" for c in ref.revision), f"{ref.repo_id}: not a hex SHA"


def test_registry_has_no_duplicate_repos():
    repos = [r.repo_id for r in ALL]
    assert len(repos) == len(set(repos))


def test_no_module_hardcodes_a_model_identifier():
    """Identifiers used to be repeated across detectors, prewarm and the README.

    That duplication is how prewarm and the runtime defaults drifted apart, and
    how a 401'ing repository stayed configured long enough to break the build.
    """
    import pathlib

    app_dir = pathlib.Path(__file__).resolve().parent.parent / "app"
    known = {r.repo_id for r in ALL}
    offenders = []
    for py in app_dir.rglob("*.py"):
        if py.name == "model_registry.py":
            continue
        text = py.read_text()
        for repo_id in known:
            if f'"{repo_id}"' in text:
                offenders.append(f"{py.relative_to(app_dir.parent)}: {repo_id}")
    assert not offenders, "model identifiers must come from app.model_registry: " + "; ".join(offenders)


# ---------------------------------------------------------------------------
# Network — opt-in
# ---------------------------------------------------------------------------


def _hf_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.loads(resp.read())


@_NETWORK
@pytest.mark.parametrize("ref", ALL, ids=lambda r: r.repo_id)
def test_reference_is_public_and_ungated(ref: ModelRef):
    meta = _hf_json(_HF_API.format(repo_id=ref.repo_id))

    assert meta.get("gated") in (False, None), f"{ref.repo_id} is gated: a clean build cannot fetch it"
    assert meta.get("private") is not True, f"{ref.repo_id} is private"


@_NETWORK
@pytest.mark.parametrize("ref", ALL, ids=lambda r: r.repo_id)
def test_pinned_revision_resolves_anonymously(ref: ModelRef):
    """With no HF token, exactly as a clean Docker build sees it."""
    url = _HF_FILE.format(repo_id=ref.repo_id, revision=ref.revision)
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=30) as resp:
            assert resp.status == 200
    except urllib.error.HTTPError as exc:  # pragma: no cover - the failure we care about
        pytest.fail(f"{ref.repo_id}@{ref.revision[:12]} returned HTTP {exc.code} anonymously")


@_NETWORK
@pytest.mark.parametrize("ref", ALL, ids=lambda r: r.repo_id)
def test_pipeline_tag_matches_how_the_code_uses_it(ref: ModelRef):
    meta = _hf_json(_HF_API.format(repo_id=ref.repo_id))
    published = meta.get("pipeline_tag")

    if published is None:
        pytest.skip(f"{ref.repo_id} publishes no pipeline_tag")
    assert published == ref.pipeline_tag, (
        f"{ref.repo_id} is a {published} model but the registry declares {ref.pipeline_tag}"
    )
