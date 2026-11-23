"""Native policy semantics against actual, bounded SQLite configuration."""

from dataclasses import FrozenInstanceError

import pytest
from sqlalchemy import event, text

from app.db.engine import get_engine, get_session_factory
from app.db.models import AccessRule, Base, GlobalPromptList, Policy, RuleSet
from app.services.prompt_classifier_client import MODEL_IDENTITY, PROFILE, SCORE_KIND, AssessmentResult
from app.services.prompt_list_service import PromptListConfigError, PromptListService
from app.services.safe_regex import MAX_PATTERNS


@pytest.fixture
def db():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with get_session_factory(engine)() as session:
        policy = Policy(id="p", name="Native")
        rules = RuleSet(id="rs", policy=policy, event_type="input", detectors={"malicious_prompt": {"action": "block"}})
        session.add(rules)
        session.commit()
        yield session
    engine.dispose()


def native():
    from app.services import native_prompt_policy

    return native_prompt_policy


def freeze(db, **options):
    config = native().NativePolicyConfig(
        **{"enabled": True, "profile": PROFILE, "threshold": 0.5, "generation": 1, **options}
    )
    db.commit()
    db.execute(text("BEGIN IMMEDIATE"))
    try:
        return native().freeze_native_policy(db, "p", config)
    finally:
        db.commit()


def rule(db, *, id="r", conditions=None, then="block_and_stop", otherwise="continue", order=0):
    db.add(
        AccessRule(
            id=id,
            rule_set_id="rs",
            name="operator rule",
            conditions=({"field": "app_id", "value": "claude-code"} if conditions is None else conditions),
            then_action=then,
            else_action=otherwise,
            sort_order=order,
        )
    )


def model(score):
    return AssessmentResult("assessed", None, PROFILE, MODEL_IDENTITY, score, SCORE_KIND, 27)


def outcome(snap, prompt, assessment=None):
    check = native().evaluate_native_precheck(snap, prompt)
    return native().resolve_native_result(snap, check, assessment)


def no_score(assessment):
    assert (assessment.model_identity, assessment.unsafe_score, assessment.score_kind, assessment.input_tokens) == (
        None,
        None,
        None,
        None,
    )


@pytest.mark.parametrize(
    ("kind", "pattern", "sample", "expected"),
    [
        ("exact", "Café", "CAFÉ", True),
        ("exact", " hi ", "HI", False),
        ("substring", "ß", "GRÖSSE", False),
        ("substring", "ÁB", "xábx", True),
        ("regex", r"^name\s+\d+$", "NAME 42", True),
        ("regex", "^i$", "İ", False),
    ],
)
def test_legacy_list_characterization(db, kind, pattern, sample, expected):
    svc = PromptListService(db)
    svc.create("malicious", pattern, kind)
    assert svc.check_match(sample, "malicious") is expected


def test_legacy_stored_invalid_regex_raises(db):
    db.add(GlobalPromptList(list_type="benign", pattern="(?=x)x", match_type="regex"))
    db.commit()
    with pytest.raises(PromptListConfigError):
        PromptListService(db).check_match("x", "benign")


@pytest.mark.parametrize(
    ("score", "policy_report", "override", "action", "evaluated", "returned", "reason"),
    [
        (0.499, False, None, "block", "allow", "allow", "clean"),
        (0.5, False, None, "block", "deny", "deny", "classifier_positive"),
        (0.5, True, None, "block", "deny", "allow", "classifier_positive"),
        (0.5, True, False, "block", "deny", "deny", "classifier_positive"),
        (1, False, True, "block", "deny", "allow", "classifier_positive"),
        (0.8, False, None, "report", "allow", "allow", "classifier_positive"),
    ],
)
def test_model_resolution(db, score, policy_report, override, action, evaluated, returned, reason):
    db.get(Policy, "p").report_only = policy_report
    rs = db.get(RuleSet, "rs")
    rs.report_only = override
    rs.detectors = {"malicious_prompt": {"action": action}}
    snap = freeze(db)
    assert native().evaluate_native_precheck(snap, "one prompt").needs_assessment
    result = outcome(snap, "one prompt", model(score))
    assert (result.evaluated_action, result.returned_action, result.reason) == (evaluated, returned, reason)
    assert result.assessment.reason == reason
    assert (
        result.assessment.unsafe_score,
        result.assessment.model_identity,
        result.assessment.input_tokens,
        result.assessment.score_kind,
    ) == (score, MODEL_IDENTITY, 27, SCORE_KIND)


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        ("unsupported", "input_unsupported"),
        ("unsupported", "input_too_large"),
        ("unavailable", "deadline_exceeded"),
        ("unavailable", "classifier_unavailable"),
        ("failed", "classifier_invalid"),
    ],
)
@pytest.mark.parametrize(
    ("failure", "detector", "actions"),
    [
        ("block", "block", ("deny", "deny")),
        ("report", "block", ("unknown", "allow")),
        ("block", "report", ("unknown", "allow")),
    ],
)
def test_incomplete_input_and_model_failure(db, status, reason, failure, detector, actions):
    p = db.get(Policy, "p")
    p.report_only, p.on_detector_failure = True, failure
    db.get(RuleSet, "rs").detectors = {"malicious_prompt": {"action": detector}}
    result = outcome(freeze(db), None if status == "unsupported" else "synthetic", AssessmentResult(status, reason))
    assert (result.evaluated_action, result.returned_action) == actions
    assert (result.assessment.status, result.assessment.reason, result.reason) == (status, reason, reason)
    no_score(result.assessment)


def test_capture_disabled_is_rule_only_even_under_failure_block(db):
    db.get(Policy, "p").on_detector_failure = "block"
    snap = freeze(db)
    assert not native().evaluate_native_precheck(snap, None).needs_assessment
    result = outcome(snap, None)
    assert (result.assessment.status, result.reason, result.returned_action) == (
        "not_requested",
        "capture_disabled",
        "allow",
    )
    no_score(result.assessment)


@pytest.mark.parametrize(
    "condition",
    [
        {"field": "app_id", "op": "in", "value": ["claude-code"]},
        {"field": "app_id", "op": "typo", "value": "claude-code"},
    ],
)
def test_access_block_precedes_detector_in_shadow_and_outage(db, condition):
    rule(db, conditions=condition)
    db.get(Policy, "p").report_only = True
    snap = freeze(db)
    check = native().evaluate_native_precheck(snap, "one prompt")
    assert not check.needs_assessment
    result = native().resolve_native_result(snap, check, AssessmentResult("unavailable", "classifier_unavailable"))
    assert (result.reason, result.evaluated_action, result.returned_action) == ("access_rule_block", "deny", "deny")
    no_score(result.assessment)
    result = outcome(snap, None, AssessmentResult("unsupported", "input_too_large"))
    assert (result.reason, result.returned_action) == ("access_rule_block", "deny")
    assert (result.assessment.status, result.assessment.reason) == ("unsupported", "input_too_large")


@pytest.mark.parametrize("stop", ["report_and_stop", "ignore_and_stop"])
def test_tied_rule_order_native_stop_still_reaches_detectors(db, stop):
    rule(db, id="z")
    rule(db, id="a", then=stop)
    snap = freeze(db)
    assert [r.id for r in snap.rules] == ["a", "z"]
    assert outcome(snap, "exact", model(0)).reason == "clean"


@pytest.mark.parametrize(
    "detectors",
    [
        {},
        {"malicious_prompt": {"enabled": False}},
        {"malicious_prompt": {"generic_injection_detection": False}},
        {"malicious_prompt": {"intent_conformance": {"enabled": True}}},
        {"malicious_prompt": {}, "topic": {}},
        {"malicious_prompt": {"action": "redact"}},
        {"malicious_prompt": {"action": "defang"}},
        {"malicious_prompt": {"action": "transform"}},
        {"malicious_prompt": {"custom_benign_detection": "false"}},
    ],
)
def test_refuses_unrepresentable_detector_config(db, detectors):
    db.get(RuleSet, "rs").detectors = detectors
    with pytest.raises(native().NativePolicyUnsupported):
        freeze(db)


@pytest.mark.parametrize(
    "conditions",
    [
        {"field": "user_id", "value": ""},
        {"field": "model", "value": "claude-code"},
        {"field": "llm_provider", "value": ""},
        {"field": "source_ip", "value": "ip"},
        {"all": [{"field": "app_id", "value": "claude-code"}]},
        [{"field": "app_id", "value": "claude-code"}],
        {},
        {"field": "app_id", "value": "x", "operator": "!="},
        {"field": "app_id", "op": "in", "value": "x"},
        {"field": "app_id", "op": "contains", "value": ["x"]},
    ],
)
def test_refuses_unrepresentable_access_condition(db, conditions):
    rule(db, conditions=conditions)
    with pytest.raises(native().NativePolicyUnsupported):
        freeze(db)


@pytest.mark.parametrize(
    "options",
    [
        {"enabled": False},
        {"profile": "other"},
        *({"threshold": x} for x in [float("nan"), float("inf"), -0.1, 1.1, True]),
    ],
)
def test_refuses_unusable_native_config(db, options):
    with pytest.raises(native().NativePolicyUnsupported):
        freeze(db, **options)


def test_requires_input_rule_set(db):
    db.get(RuleSet, "rs").event_type = "output"
    with pytest.raises(native().NativePolicyUnsupported):
        freeze(db)


def lists(db, **settings):
    db.get(RuleSet, "rs").detectors = {
        "malicious_prompt": {
            "action": "block",
            "custom_malicious_detection": True,
            "custom_benign_detection": True,
            **settings,
        }
    }


def test_live_lists_refreeze_in_cached_session_and_snapshots_are_detached(db):
    lists(db)
    row = PromptListService(db).create("malicious", "FIRST", "exact")
    before = db.get(Policy, "p").updated_at
    original = freeze(db)
    with get_session_factory(db.get_bind())() as writer:
        PromptListService(writer).update(row.id, pattern="SECOND")
    changed = freeze(db)
    with get_session_factory(db.get_bind())() as writer:
        PromptListService(writer).update(row.id, pattern="FIRST")
    restored = freeze(db, generation=3)
    assert original.revision != changed.revision
    assert original.revision == restored.revision
    assert original.config.generation != restored.config.generation
    assert db.get(Policy, "p").updated_at == before
    db.close()
    assert outcome(original, "first").reason == "malicious_list"
    assert native().evaluate_native_precheck(changed, "first").needs_assessment
    with pytest.raises(FrozenInstanceError):
        original.malicious_entries[0].pattern = "new"


def test_revision_tracks_effective_flags_mode_rules_threshold_failure_and_action(db):
    base = freeze(db)
    assert len(base.revision) == 64 and int(base.revision, 16)
    assert freeze(db, threshold=0.9).revision != base.revision
    p = db.get(Policy, "p")
    p.report_only = True
    assert freeze(db).revision != base.revision
    p.report_only = False
    p.on_detector_failure = "block"
    assert freeze(db).revision != base.revision
    p.on_detector_failure = "report"
    rule(db, id="a", then="continue")
    rules = freeze(db)
    assert rules.revision != base.revision
    db.get(AccessRule, "a").conditions = {"field": "app_id", "value": "x"}
    assert freeze(db).revision != rules.revision
    db.delete(db.get(AccessRule, "a"))
    rs = db.get(RuleSet, "rs")
    rs.detectors = {"malicious_prompt": {"action": "report"}}
    assert freeze(db).revision != base.revision
    rs.detectors = {"malicious_prompt": {"action": "block", "custom_benign_detection": True}}
    assert freeze(db).revision != base.revision
    rs.detectors = {"malicious_prompt": {"action": "block", "custom_malicious_detection": True}}
    assert freeze(db).revision != base.revision


@pytest.mark.parametrize(
    ("text_value", "reason", "evaluated"),
    [("both", "malicious_list", "deny"), ("only benign", "benign_override", "allow")],
)
def test_list_overrides_skip_generic_and_shadow_downgrades_finding(db, text_value, reason, evaluated):
    lists(db)
    db.get(Policy, "p").report_only = True
    svc = PromptListService(db)
    svc.create("malicious", "both", "exact")
    svc.create("benign", "both", "exact")
    svc.create("benign", "only benign", "exact")
    snap = freeze(db)
    assert not native().evaluate_native_precheck(snap, text_value).needs_assessment
    result = outcome(snap, text_value)
    assert (result.reason, result.evaluated_action, result.returned_action) == (reason, evaluated, "allow")
    assert result.assessment.status == "not_requested"
    no_score(result.assessment)


@pytest.mark.parametrize(("failure", "expected"), [("block", ("deny", "deny")), ("report", ("unknown", "allow"))])
def test_earlier_operational_list_failure_survives_benign_match(db, monkeypatch, failure, expected):
    lists(db)
    p = db.get(Policy, "p")
    p.report_only, p.on_detector_failure = True, failure
    svc = PromptListService(db)
    svc.create("malicious", "^never$", "regex")
    svc.create("benign", "approved", "exact")
    snap = freeze(db)

    # Induce a runtime failure below the preflighted, frozen matcher.
    class BrokenSearch:
        def search(self, sample):
            raise RuntimeError("synthetic RE2 failure")

    monkeypatch.setattr("app.services.prompt_list_service.compile_pattern", lambda *a, **k: BrokenSearch())
    result = outcome(snap, "approved")
    assert (result.assessment.status, result.assessment.reason, result.reason) == (
        "failed",
        "prompt_list_failed",
        "prompt_list_failed",
    )
    assert (result.evaluated_action, result.returned_action) == expected
    no_score(result.assessment)


def test_freeze_refuses_bad_stored_list_even_behind_match(db):
    lists(db)
    db.add_all(
        [
            GlobalPromptList(list_type="benign", pattern="(?=x)x", match_type="regex"),
            GlobalPromptList(list_type="benign", pattern="x", match_type="exact"),
        ]
    )
    with pytest.raises(native().NativePolicyUnsupported):
        freeze(db)


@pytest.mark.parametrize("kind", ["rules", "malicious", "benign"])
def test_bounded_snapshot_queries_accept_limit_and_refuse_one_extra(db, kind):
    lists(db)
    bound = 64 if kind == "rules" else MAX_PATTERNS

    def add(i):
        if kind == "rules":
            rule(db, id=str(i), then="continue")
        else:
            db.add(GlobalPromptList(list_type=kind, pattern="p" + str(i), match_type="exact"))

    for i in range(bound):
        add(i)
    selects = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            selects.append((statement.lower(), parameters))

    engine = db.get_bind()
    event.listen(engine, "before_cursor_execute", capture)
    try:
        snap = freeze(db)
        assert len(snap.rules if kind == "rules" else getattr(snap, kind + "_entries")) == bound
        add(bound)
        with pytest.raises(native().NativePolicyUnsupported):
            freeze(db)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    table = "access_rules" if kind == "rules" else "global_prompt_lists"
    reads = [(sql, args) for sql, args in selects if table in sql]
    assert reads and all("limit" in sql and bound + 1 in args for sql, args in reads)


def test_precheck_requires_normalized_single_prompt_or_explicit_absence(db):
    snap = freeze(db)
    with pytest.raises(TypeError):
        native().evaluate_native_precheck(snap, {"prompt": "synthetic"})
    with pytest.raises(ValueError):
        outcome(snap, "ordinary")


def test_unknown_operator_on_membership_shape_still_denies(db):
    rule(db, conditions={"field": "app_id", "op": "member", "value": ["claude-code"]})
    result = outcome(freeze(db), None)
    assert (result.returned_action, result.reason) == ("deny", "access_rule_block")


def test_invalid_stored_blob_pattern_refused_at_activation(db):
    lists(db)
    # A direct SQLite write can put a blob in a VARCHAR column.
    db.add(GlobalPromptList(list_type="malicious", pattern=b"synthetic", match_type="substring"))
    with pytest.raises(native().NativePolicyUnsupported):
        freeze(db)


def test_disabled_guard_components_and_guard_model_do_not_change_native_revision(db):
    before = freeze(db).revision
    db.get(RuleSet, "rs").detectors = {
        "malicious_prompt": {"model": "guard-model", "threshold": 0.99, "action": "block"},
        "topic": {"enabled": False, "action": "redact"},
    }
    assert freeze(db).revision == before


def test_activation_refuses_regex_that_fails_only_with_matching_options(db, monkeypatch):
    from app.services import prompt_list_service
    from app.services.safe_regex import UnsafePatternError

    lists(db)
    svc = PromptListService(db)
    svc.create("malicious", "^sample$", "regex")
    compiler = prompt_list_service.compile_pattern

    def restricted_compiler(pattern, *, case_insensitive=False):
        if case_insensitive:
            raise UnsafePatternError("synthetic case-insensitive program exceeds budget")
        return compiler(pattern)

    monkeypatch.setattr(prompt_list_service, "compile_pattern", restricted_compiler)
    with pytest.raises(PromptListConfigError):
        svc.check_match("SAMPLE", "malicious")
    with pytest.raises(native().NativePolicyUnsupported):
        freeze(db)


@pytest.mark.parametrize(("column", "value"), [("name", b"rule"), ("id", b"id"), ("sort_order", 1.5)])
def test_malformed_stored_rule_scalars_refused_at_activation(db, column, value):
    rule(db)
    db.flush()
    db.execute(AccessRule.__table__.update().values({column: value}))
    with pytest.raises(native().NativePolicyUnsupported):
        freeze(db)
