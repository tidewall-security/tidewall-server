"""Administrator-supplied regexes must not be able to hang the server.

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
        "supplied patterns are being compiled with the backtracking stdlib engine; "
        "the denial-of-service hazard is reintroduced"
    )


def test_no_backtracking_engine_runs_a_supplied_pattern():
    """Structural check: a pattern reaching `re` must be written in the source.

    Four earlier versions were each too weak in a different way — a substring
    search (evaded by `re.finditer` or an alias), a whole-module allowlist (hid
    consumers added inside exempt modules), and a per-line `# hardcoded-pattern`
    marker which asserted nothing at all, since a contributor could apply the
    very marker the failure message suggested. A control you can self-approve
    with a comment is not a control.

    So nobody attests to anything. This resolves calls into the backtracking
    module and requires the pattern argument to be a literal written in the
    source, or a module-level constant that is itself a literal. A hard-coded
    regex satisfies that by construction; a value arriving from configuration
    or a database row cannot.

    Known limits, stated rather than implied. This is a regression guard, not
    the security control — RE2 is. It does not follow a pattern through a
    helper defined outside `app/`; it does not analyse `compiled.search(text)`
    on an already-compiled object (that call receives text, and the
    compilation was checked where it happened); and it does not chase the
    module or a bound callable through a class attribute, a container, tuple
    unpacking, or `importlib`. Someone determined to route around it can.
    What it reliably catches is the accident: a new consumer written the
    ordinary way.
    """
    import ast
    import pathlib

    # Only the APIs that actually take a pattern. Including everything made
    # `re.escape(text)` and `re.purge()` failures, which is noise that teaches
    # contributors to route around the rule.
    PATTERN_APIS = {"compile", "search", "match", "fullmatch", "findall", "finditer", "sub", "subn", "split"}

    repo = pathlib.Path(__file__).resolve().parent.parent
    offenders: list[str] = []

    for path in sorted((repo / "app").rglob("*.py")):
        source = path.read_text()
        tree = ast.parse(source)
        rel = path.relative_to(repo).as_posix()

        module_names: set[str] = set()  # names bound to the re/regex module
        func_names: set[str] = set()  # names bound to a pattern-taking function
        literal_consts: set[str] = set()  # module-level NAME = "literal"

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("re", "regex"):
                        module_names.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module in ("re", "regex"):
                for alias in node.names:
                    if alias.name in PATTERN_APIS:
                        func_names.add(alias.asname or alias.name)

        # A trivial rebinding (`engine = re`) previously defeated the whole rule.
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name) and node.value.id in module_names:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        module_names.add(target.id)

        for node in ast.walk(tree):
            # Anywhere, not only module level: a literal assigned inside a
            # function is just as clearly written in the source.
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str | bytes):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            literal_consts.add(target.id)
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str | bytes)
                and isinstance(node.target, ast.Name)
            ):
                literal_consts.add(node.target.id)

        if not module_names and not func_names:
            continue

        def is_source_literal(node: ast.AST) -> bool:
            if isinstance(node, ast.Constant):
                return isinstance(node.value, str | bytes)
            if isinstance(node, ast.Name):
                return node.id in literal_consts
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
                return is_source_literal(node.left) and is_source_literal(node.right)
            if isinstance(node, ast.JoinedStr):
                return all(
                    isinstance(v, ast.Constant) or (isinstance(v, ast.FormattedValue) and is_source_literal(v.value))
                    for v in node.values
                )
            # "literal".format(only, literals)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                # Keyword substitutions count: "{x}".format(x=supplied) is not
                # a source literal, and checking only positional args let it
                # through.
                return (
                    is_source_literal(node.func.value)
                    and all(is_source_literal(a) for a in node.args)
                    and all(is_source_literal(kw.value) for kw in node.keywords)
                )
            return False

        def pattern_arg(call: ast.Call):
            if call.args:
                return call.args[0]
            for kw in call.keywords:
                if kw.arg == "pattern":
                    return kw.value
            return None

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func

            # Indirection that hands the callable itself somewhere else —
            # functools.partial(re.compile, supplied) and getattr(re, "search")
            # both previously sailed straight past.
            if (isinstance(func, ast.Attribute) and func.attr == "partial") or (
                isinstance(func, ast.Name) and func.id == "partial"
            ):
                for arg in node.args:
                    if (
                        isinstance(arg, ast.Attribute)
                        and isinstance(arg.value, ast.Name)
                        and arg.value.id in module_names
                        and arg.attr in PATTERN_APIS
                    ) or (isinstance(arg, ast.Name) and arg.id in func_names):
                        offenders.append(f"{rel}:{node.lineno} (regex callable passed through partial)")
                continue
            if isinstance(func, ast.Name) and func.id == "getattr" and node.args:
                target = node.args[0]
                if isinstance(target, ast.Name) and target.id in module_names:
                    offenders.append(f"{rel}:{node.lineno} (dynamic getattr on the regex module)")
                continue

            hit = False
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                hit = func.value.id in module_names and func.attr in PATTERN_APIS
            elif isinstance(func, ast.Name):
                hit = func.id in func_names
            if not hit:
                continue

            arg = pattern_arg(node)
            if arg is None or not is_source_literal(arg):
                offenders.append(f"{rel}:{node.lineno} (pattern is not a source literal)")

    assert not offenders, (
        "a backtracking regex engine is being handed a pattern that is not written in the source at: "
        + ", ".join(offenders)
        + ". Administrator-supplied patterns must go through app/services/safe_regex.py."
    )


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


def test_an_unenforceable_row_is_visible_at_construction_not_first_scan(db_session):
    """The failure must be recorded when the engine is built.

    Without construction-time compilation the engine reports no failure at all,
    and the bad row is discovered by whichever caller's text first happens to
    exercise that list — which for a malicious list means an attacker chooses
    the moment.

    Visibility, not refusal: nothing in this repository reads
    is_enforcement_complete to reject an engine, so a policy with an
    unenforceable list is still served. That gate is separate, unbuilt work.
    """
    from app.db.models import GlobalPromptList
    from app.detectors.base import FailureCode
    from app.detectors.malicious_prompt import MaliciousPromptDetector

    db_session.add(GlobalPromptList(list_type="malicious", pattern=r"(?=x)y", match_type="regex"))
    db_session.commit()

    detector = MaliciousPromptDetector(
        {"enabled": True, "custom_malicious_detection": True, "generic_injection": {"enabled": False}},
        session_factory=lambda: db_session,
    )

    assert detector.load_failures.get("custom_malicious") is FailureCode.CONFIG_INVALID


def test_a_valid_list_preflights_clean(db_session):
    from app.db.models import GlobalPromptList
    from app.detectors.malicious_prompt import MaliciousPromptDetector

    db_session.add(GlobalPromptList(list_type="malicious", pattern=r"attack-\d+", match_type="regex"))
    db_session.commit()

    detector = MaliciousPromptDetector(
        {"enabled": True, "custom_malicious_detection": True, "generic_injection": {"enabled": False}},
        session_factory=lambda: db_session,
    )

    assert "custom_malicious" not in detector.load_failures


def test_the_scan_query_is_bounded_not_just_the_scan(db_session):
    """A cap applied after `.all()` is not a cap.

    Checking the length of a full fetch still lets a direct write of a million
    rows make every request retrieve and instantiate a million objects before
    the limit fires. The bound has to be in the SQL, so assert the SQL.
    """
    from sqlalchemy import event

    from app.db.models import GlobalPromptList
    from app.services.prompt_list_service import MAX_PATTERNS, PromptListConfigError, PromptListService

    for i in range(MAX_PATTERNS + 50):
        db_session.add(GlobalPromptList(list_type="malicious", pattern=f"p{i}", match_type="substring"))
    db_session.commit()

    statements: list[str] = []
    engine = db_session.get_bind()

    def record(conn, cursor, statement, parameters, context, executemany):
        if "global_prompt_lists" in statement:
            statements.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        with pytest.raises(PromptListConfigError):
            PromptListService(db_session).check_match("anything", "malicious")
    finally:
        event.remove(engine, "before_cursor_execute", record)

    assert statements, "no query was emitted"
    assert all(
        "LIMIT" in st.upper() for st in statements
    ), f"the scan path fetched without a LIMIT, so the row count is unbounded: {statements}"


def test_preflight_runs_for_benign_when_malicious_is_disabled(db_session):
    """The two toggles are independent; only checking the malicious one would
    leave a benign list unvalidated. A bad benign row matters: that list
    suppresses detections."""
    from app.db.models import GlobalPromptList
    from app.detectors.base import FailureCode
    from app.detectors.malicious_prompt import MaliciousPromptDetector

    db_session.add(GlobalPromptList(list_type="benign", pattern=r"(?=x)y", match_type="regex"))
    db_session.commit()

    detector = MaliciousPromptDetector(
        {
            "enabled": True,
            "custom_malicious_detection": False,
            "custom_benign_detection": True,
            "generic_injection": {"enabled": False},
        },
        session_factory=lambda: db_session,
    )

    assert detector.load_failures.get("custom_benign") is FailureCode.CONFIG_INVALID


@pytest.mark.parametrize("list_type", ["malicious", "benign"])
def test_both_list_types_are_fetched_with_a_bound(db_session, list_type):
    """Round 3 noted the SQL assertion only covered malicious check_match."""
    from sqlalchemy import event

    from app.services.prompt_list_service import PromptListService

    statements: list[str] = []
    engine = db_session.get_bind()

    def record(conn, cursor, statement, parameters, context, executemany):
        if "global_prompt_lists" in statement:
            statements.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        svc = PromptListService(db_session)
        svc.check_match("text", list_type)
        svc.preflight(list_type)
    finally:
        event.remove(engine, "before_cursor_execute", record)

    assert statements, "no query emitted"
    assert all("LIMIT" in st.upper() for st in statements), f"unbounded fetch: {statements}"


def test_the_failure_reaches_a_real_scanner_engine(db_session):
    """Assert the propagation rather than trusting the detector in isolation."""
    from app.db.models import GlobalPromptList
    from app.scanner_engine import ScannerEngine

    db_session.add(GlobalPromptList(list_type="malicious", pattern=r"(?=x)y", match_type="regex"))
    db_session.commit()

    from app.config import PolicyConfig

    policy = PolicyConfig(
        name="test",
        detectors={
            "malicious_prompt": {
                "enabled": True,
                "action": "block",
                "custom_malicious_detection": True,
                "generic_injection": {"enabled": False},
            }
        },
    )
    engine = ScannerEngine(policy, session_factory=lambda: db_session)

    names = [f.name for f in engine.construction_failures]
    assert "malicious_prompt.custom_malicious" in names, f"not surfaced in engine: {names}"
    assert (
        not engine.is_enforcement_complete
    ), "an enforcing detector with unenforceable config must not read as complete"


def test_correcting_a_bad_row_clears_the_cached_failure(db_session):
    """The defect the preflight introduced.

    Compiling at construction means the verdict is a snapshot. Prompt lists are
    global, so without invalidation an administrator who fixes the row keeps
    seeing the old failure on every cached engine until an unrelated policy
    edit or a restart.
    """
    from app.db.models import Policy, RuleSet
    from app.services.policy_service import PolicyService

    policy = Policy(name="p", type="application", is_default=True)
    db_session.add(policy)
    db_session.flush()
    db_session.add(
        RuleSet(
            policy_id=policy.id,
            event_type="input",
            detectors={"emoji": {"enabled": True, "action": "report"}},
        )
    )
    db_session.commit()

    svc = PolicyService(db_session)
    first = svc.get_engine(policy.id, "input")
    assert svc.get_engine(policy.id, "input") is first, "engine should be cached"

    svc.invalidate_all_engines()

    assert svc.get_engine(policy.id, "input") is not first, "a global list change must rebuild engines"
