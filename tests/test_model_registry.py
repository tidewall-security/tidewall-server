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


@_NETWORK
@pytest.mark.parametrize("ref", ALL, ids=lambda r: r.repo_id)
def test_declared_licence_matches_upstream(ref: ModelRef):
    """The registry's licence field must be enforced, not decorative.

    It was populated for every artifact and read nowhere, while NOTICE
    duplicated the same values by hand — the exact drift the registry exists to
    prevent, and the eighth instance in this work of a value produced and never
    consumed. A licence claim in NOTICE that has quietly gone stale upstream is
    worse than no claim.
    """
    meta = _hf_json(_HF_API.format(repo_id=ref.repo_id))
    published = (meta.get("cardData") or {}).get("license")

    if published is None:
        pytest.skip(f"{ref.repo_id} publishes no licence in cardData")
    assert str(published).lower() == ref.licence.lower(), (
        f"{ref.repo_id} now declares {published!r}; the registry and NOTICE say {ref.licence!r}"
    )


def test_notice_lists_every_registry_artifact():
    """NOTICE and the registry must not drift apart.

    Offline, so it runs everywhere: an artifact added to the registry without a
    NOTICE entry means the image redistributes something unattributed.
    """
    import pathlib

    notice = (pathlib.Path(__file__).resolve().parent.parent / "NOTICE").read_text()
    missing = [r.repo_id for r in ALL if r.repo_id not in notice]

    assert not missing, f"NOTICE does not attribute: {missing}"


# ---------------------------------------------------------------------------
# The pin must reach the loader, not merely exist in the registry
# ---------------------------------------------------------------------------


def test_prewarm_imports_in_a_builder_only_context():
    """The Docker builder stage runs prewarm before app/ was copied.

    Adding the registry import broke the build with ModuleNotFoundError before
    a single artifact was fetched — the same defect class as the 401'ing model
    reference this work exists to fix. This asserts the dependency is declared
    where the Dockerfile can satisfy it.
    """
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    tree = ast.parse((root / "prewarm.py").read_text())
    app_imports = {
        n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("app")
    }
    dockerfile = (root / "Dockerfile").read_text()

    builder = dockerfile.split("# ---- Runtime stage ----")[0]

    if app_imports:
        assert "COPY app" in builder, (
            f"prewarm.py imports {sorted(app_imports)} but the Docker builder stage does not copy app/"
        )
        # Ordering, not just presence. The previous version of this test only
        # looked for the substring anywhere in the builder stage, so it passed
        # while the image could not build at all: `COPY app` sat ten lines
        # after `pip install .`, which needs it. A test that reports a fixed
        # build while the build is broken is worse than no test.
        assert builder.index("COPY app") < builder.index("RUN python prewarm.py"), (
            "COPY app must precede RUN python prewarm.py"
        )

    # Hatch builds the project from pyproject metadata, which declares the
    # readme, licence and notice, plus the `app` wheel target. Copying
    # pyproject alone failed with "Readme file does not exist: README.md".
    install_at = builder.index("pip install --no-cache-dir .")
    for required in ("README.md", "LICENSE", "NOTICE", "app"):
        copies = [
            builder.index(line)
            for line in builder.splitlines()
            if line.startswith("COPY") and required in line
        ]
        assert copies, f"the Docker builder stage never copies {required}, which `pip install .` needs"
        assert min(copies) < install_at, f"{required} is copied after `pip install .`, which needs it"


def _call_bodies(source: str, loader: str) -> list[str]:
    """Argument text of every `loader(...)` call, matching parentheses properly.

    A naive scan to the first ")" stops inside a nested call and reports a
    missing revision that is actually present a few arguments later.
    """
    import re

    bodies = []
    # Constructions only. Excluding a preceding word character skips
    # `self._pipeline(text)`, which invokes the already-built pipeline and
    # takes no revision, while still matching `AutoTokenizer.from_pretrained(`
    # where the preceding character is a dot.
    pattern = re.compile(r"(?<![\w])" + re.escape(loader) + r"\(")
    for match in pattern.finditer(source):
        start = match.end()
        depth, pos = 1, start
        while pos < len(source) and depth:
            if source[pos] == "(":
                depth += 1
            elif source[pos] == ")":
                depth -= 1
            pos += 1
        bodies.append(source[start : pos - 1])
    return bodies


@pytest.mark.parametrize(
    ("module", "loader"),
    [
        ("app/detectors/language.py", "pipeline"),
        ("app/detectors/code.py", "pipeline"),
        ("app/detectors/topic.py", "pipeline"),
        ("app/detectors/malicious_entity.py", "pipeline"),
        ("app/detectors/malicious_prompt.py", "from_pretrained"),
        ("app/services/intent_conformance_service.py", "SentenceTransformer"),
    ],
)
def test_every_loader_call_passes_a_revision(module: str, loader: str):
    """The pin must reach the loader, not merely sit in the registry.

    A registry that is read but never applied is the produced-but-not-consumed
    defect that has recurred repeatedly in this codebase, and it would be
    invisible: the model still loads, just from an unpinned branch.

    Asserted at the source rather than by mocking, because transformers
    exposes `pipeline` through a lazy module that ordinary patching does not
    intercept — a mock-based test here silently exercised the real loader and
    passed while asserting nothing.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    source = (root / module).read_text()

    bodies = _call_bodies(source, loader)
    assert bodies, f"{module} does not call {loader}("

    for i, body in enumerate(bodies):
        assert "revision" in body, f"{module}: {loader}() call #{i + 1} passes no revision — the pin is not applied"


def test_an_operator_model_is_not_pinned_to_our_sha():
    """Pinning someone else's model to our commit would be wrong.

    It would either fail to resolve or, worse, fetch an unrelated commit that
    happens to exist in their repository.
    """
    from app.model_registry import LANGUAGE

    assert LANGUAGE.revision_for(LANGUAGE.repo_id) == LANGUAGE.revision
    assert LANGUAGE.revision_for("someone-else/their-model") is None
    assert LANGUAGE.revision_for(None) is None
