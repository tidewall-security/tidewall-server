"""P0-12: administrator-supplied regexes must not be able to hang the server.

Custom-entity patterns and regex prompt-list entries are written by an
administrator and matched against text supplied by whoever calls the guard.
With Python's backtracking `re`, that combination is a denial of service
waiting to be configured — `(a+)+$` against 41 characters runs for over three
seconds and does not stop, so any caller could take the guard offline.

These tests assert the property that makes that impossible: supplied patterns
are matched by a linear-time engine. They are written against inputs large
enough that a backtracking engine could not possibly complete, so a regression
to `re` fails them by timing out rather than by a flaky wall-clock threshold.
"""

from __future__ import annotations

import time

import pytest

from app.db.engine import get_engine, get_session_factory
from app.db.models import Base
from app.services.safe_regex import (
    MAX_MATCHES_PER_SCAN,
    MAX_PATTERN_LENGTH,
    MAX_PATTERNS,
    UnsafePatternError,
    compile_pattern,
)


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = get_session_factory(engine)()
    yield session
    session.close()


# Each of these is a classic catastrophic-backtracking pattern. RE2 compiles
# them happily — ambiguous repetition is perfectly legal — and matches them in
# linear time. Under `re` these do not finish in any useful timeframe.
CATASTROPHIC = [
    (r"(a+)+$", "a" * 100_000 + "!"),
    (r"(a|aa)+$", "a" * 100_000 + "!"),
    (r"^(a+)*$", "a" * 100_000 + "!"),
    (r"^([a-zA-Z]+)*$", "a" * 100_000 + "1"),
    (r"^(\w+\s?)*$", "word " * 20_000 + "!"),
    (r"a.*a.*a.*a.*a.*a.*a.*a.*a.*a!$", "a" * 100_000),
]


@pytest.mark.parametrize("pattern,text", CATASTROPHIC)
def test_a_catastrophic_pattern_completes_immediately(pattern, text):
    """The whole finding, stated as a test.

    A generous ceiling: the point is the difference between milliseconds and
    never finishing, not a precise benchmark.
    """
    compiled = compile_pattern(pattern)

    started = time.monotonic()
    compiled.search(text)
    elapsed = time.monotonic() - started

    assert elapsed < 2.0, f"{pattern!r} took {elapsed:.2f}s on {len(text)} chars — the engine is backtracking"


def test_the_engine_really_is_linear_not_merely_fast():
    """Ten times the input should not cost hugely more than ten times the time.

    A backtracking engine's cost explodes with input length. Asserting the
    shape of the growth catches a regression that a single fast case would not.
    """
    compiled = compile_pattern(r"(a+)+$")

    def timed(n: int) -> float:
        text = "a" * n + "!"
        started = time.monotonic()
        compiled.search(text)
        return time.monotonic() - started

    small = max(timed(10_000), 1e-6)
    large = timed(100_000)

    assert large < small * 100, f"10x the input cost {large / small:.0f}x the time; that is not linear"


@pytest.mark.parametrize(
    "pattern",
    [
        r"(\w+)\1",  # backreference
        r"(?=secret)x",  # lookahead
        r"(?!secret)x",  # negative lookahead
        r"(?<=secret)x",  # lookbehind
        r"(?<!secret)x",  # negative lookbehind
    ],
)
def test_constructs_that_require_backtracking_are_refused(pattern):
    """Refusing these is the point, not a limitation to work around.

    They cannot be matched in linear time, so accepting them would mean
    accepting the vulnerability. The refusal must be explicit rather than a
    silent skip, which would drop the rule the administrator wrote.
    """
    with pytest.raises(UnsafePatternError, match="unsupported construct"):
        compile_pattern(pattern)


def test_a_malformed_pattern_is_not_reported_as_an_unsupported_construct():
    """An author whose pattern is simply broken should be told that.

    Conflating the two would tell someone their working Python pattern is
    malformed, which is wrong and gives them nothing to act on.
    """
    with pytest.raises(UnsafePatternError) as exc:
        compile_pattern("(unclosed")

    assert "unsupported construct" not in str(exc.value)


def test_an_overlong_pattern_is_refused():
    with pytest.raises(UnsafePatternError, match="over the"):
        compile_pattern("a" * (MAX_PATTERN_LENGTH + 1))


def test_case_insensitivity_is_explicit_not_a_pattern_prefix():
    assert compile_pattern("SECRET", case_insensitive=True).search("my secret")
    assert compile_pattern("SECRET").search("my secret") is None


def test_compile_errors_do_not_reach_stderr(capfd):
    """RE2 logs every parse failure through absl by default.

    We raise a proper error, so that output is noise — and it is noise an
    outside caller can provoke, which makes it a way to flood an operator's
    logs.
    """
    with pytest.raises(UnsafePatternError):
        compile_pattern(r"(?=x)y")

    captured = capfd.readouterr()
    assert "re2.cc" not in captured.err
    assert "invalid perl operator" not in captured.err


def test_the_match_budget_is_smaller_than_a_pathological_input():
    """Guards the assumption the detector's cap relies on."""
    assert MAX_MATCHES_PER_SCAN < 100_000


def test_the_compiled_object_is_not_a_stdlib_re_pattern():
    """Fail fast, and unambiguously, if someone routes this back through `re`.

    The timing tests above would catch that too, but only by hanging: a
    backtracking engine never finishes on a 100,000-character input, so CI
    would time out rather than report a failure. This says what went wrong in
    the first second.
    """
    import re

    compiled = compile_pattern(r"(a+)+$")

    assert not isinstance(compiled, re.Pattern), (
        "supplied patterns are being compiled with the backtracking stdlib engine; " "this is P0-12 reintroduced"
    )


def test_every_supplied_pattern_site_uses_the_safe_compiler():
    """The chokepoint only works if nothing bypasses it.

    A new `re.compile` on an administrator-supplied pattern would reintroduce
    the finding at that site while every test here still passed, so assert the
    absence directly.
    """
    import pathlib

    repo = pathlib.Path(__file__).resolve().parent.parent
    offenders = []
    for module in (
        "app/detectors/custom_entity.py",
        "app/services/prompt_list_service.py",
        "app/services/policy_validation.py",
    ):
        source = (repo / module).read_text()
        if "re.compile(" in source or "re.search(" in source:
            offenders.append(module)

    assert not offenders, f"stdlib regex calls on supplied patterns in: {offenders}"


# ---------------------------------------------------------------------------
# The consumers, not just the compiler
#
# The tests above prove compile_pattern() is linear. They say nothing about
# whether the detector and the prompt list actually use it, which is the part
# that matters — the finding is about those two paths, not about the module.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pattern,text", CATASTROPHIC)
def test_the_custom_entity_detector_survives_a_catastrophic_pattern(pattern, text):
    from app.detectors.custom_entity import CustomEntityDetector

    detector = CustomEntityDetector({"enabled": True, "patterns": [pattern]})

    started = time.monotonic()
    detector.scan(text)
    elapsed = time.monotonic() - started

    assert elapsed < 2.0, f"custom_entity took {elapsed:.2f}s — it is not using the linear engine"


@pytest.mark.parametrize("pattern,text", CATASTROPHIC)
def test_the_prompt_list_survives_a_catastrophic_pattern(pattern, text, db_session):
    from app.services.prompt_list_service import PromptListService

    svc = PromptListService(db_session)
    svc.create(list_type="malicious", pattern=pattern, match_type="regex")

    started = time.monotonic()
    svc.check_match(text, "malicious")
    elapsed = time.monotonic() - started

    assert elapsed < 2.0, f"check_match took {elapsed:.2f}s — it is not using the linear engine"


def test_the_match_cap_reports_failure_rather_than_a_partial_scan():
    """A truncated result from a redactor is worse than an error.

    `.?` matches once per character, so a long input blows the cap. Returning
    the spans found so far would hand back text the caller believes was fully
    sanitised.
    """
    from app.detectors.base import DetectorStatus, FailureCode
    from app.detectors.custom_entity import CustomEntityDetector

    detector = CustomEntityDetector({"enabled": True, "patterns": ["a?"]})

    result = detector.scan("a" * (MAX_MATCHES_PER_SCAN * 2))

    assert result.status is DetectorStatus.FAILED
    assert result.failure_code is FailureCode.SCAN_FAILED
    assert result.detected is False


def test_a_scan_just_under_the_cap_still_succeeds():
    """The cap must not fire on ordinary input."""
    from app.detectors.base import DetectorStatus
    from app.detectors.custom_entity import CustomEntityDetector

    detector = CustomEntityDetector({"enabled": True, "patterns": ["x"]})

    result = detector.scan("x" * (MAX_MATCHES_PER_SCAN - 1))

    assert result.status is DetectorStatus.OK


def test_too_many_patterns_makes_the_detector_unavailable_not_partial():
    """Enforcing the first N would silently drop the rest of the policy."""
    from app.detectors.base import DetectorStatus
    from app.detectors.custom_entity import CustomEntityDetector

    detector = CustomEntityDetector({"enabled": True, "patterns": [f"p{i}" for i in range(MAX_PATTERNS + 1)]})

    assert not detector.available
    assert detector.scan("p1").status is DetectorStatus.FAILED


def test_an_unenforceable_stored_pattern_is_config_invalid_not_a_scan_failure(db_session):
    """Retrying will never fix a bad row; the message should say so."""
    from app.db.models import GlobalPromptList
    from app.services.prompt_list_service import PromptListConfigError, PromptListService

    # Bypass validation the way a direct database write would.
    db_session.add(GlobalPromptList(list_type="malicious", pattern=r"(?=x)y", match_type="regex"))
    db_session.commit()

    with pytest.raises(PromptListConfigError):
        PromptListService(db_session).check_match("anything", "malicious")


@pytest.mark.parametrize(
    "pattern,text",
    [
        ("i", "İ"),  # dotted capital I
        ("ı", "I"),  # dotless lowercase i
    ],
)
def test_the_known_unicode_case_folding_difference_is_pinned(pattern, text):
    """RE2 case-insensitivity is not exactly `re.IGNORECASE`.

    Pinned rather than fixed: it is the cost of the linear guarantee, and the
    point is that nobody should claim exact compatibility. If a future engine
    or option changes this, the change should be deliberate and visible.
    """
    import re

    assert re.search(pattern, text, re.IGNORECASE) is not None
    assert compile_pattern(pattern, case_insensitive=True).search(text) is None


@pytest.mark.parametrize("pattern,text", [("k", "K"), ("s", "ſ")])
def test_ordinary_unicode_folds_still_agree(pattern, text):
    """The divergence is narrow — bound it, so the pinned test above is not read
    as 'RE2 case folding is broadly different'."""
    import re

    assert re.search(pattern, text, re.IGNORECASE) is not None
    assert compile_pattern(pattern, case_insensitive=True).search(text) is not None
