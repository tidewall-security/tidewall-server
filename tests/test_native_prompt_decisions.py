import hashlib
import time
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import text

from app.db.models import Policy, RuleSet
from app.services.prompt_classifier_client import MODEL_IDENTITY, AssessmentResult
from tests import test_native_prompt_grants as grants
from tests.test_agent_event_ingest import counts, provision
from tests.test_native_prompt_contract import META
from tests.test_native_prompt_grants import CAP, OBS, enable, issue

fleet = grants.fleet
store = grants.store

DECIDE = "/v1/native-prompt/decisions"
DELIVER = "/v1/native-prompt/deliveries"
AUDIT = ("interactions", "interaction_contents", "content_export_attempts", "agent_observations", "vaults")
PROMPT = "  Synthetic complete assessment string Ω\n"


def request_body(state="complete"):
    return dict(
        version=1,
        request_id=str(uuid4()),
        observation={**META, "occurrence_id": str(uuid4())},
        input_state=state,
        budget_ms=1800,
        **({"prompt": PROMPT} if state == "complete" else {}),
    )


class Classifier:
    def __init__(self):
        self.calls = []
        self.result = AssessmentResult(
            "assessed",
            None,
            model_identity=MODEL_IDENTITY,
            unsafe_score=0.75,
            input_tokens=72,
            score_kind="two_class_softmax_uncalibrated",
        )
        self.during = None

    async def assess(self, prompt, *, request_id, deadline):
        self.calls.append((prompt.text, request_id, deadline))
        if self.during:
            await self.during()
        return self.result


def install_service(client, sessions, classifier):
    from app.services.native_prompt_decisions import NativeDecisionService

    service = NativeDecisionService(sessions, classifier, process_id=uuid4())
    client.app.state.native_decisions = service
    return service


def credentials(f, capture=True):
    client, head, _, _, _, _ = f
    meta = issue(f).json()
    headers = {**head, CAP: meta["capability"]}
    if capture:
        receipt = client.post(OBS, headers=headers, json=META).json()
        meta = issue(f, capture_allowed=True, session_id=receipt["session_id"]).json()
        headers[CAP] = meta["capability"]
    return headers, meta


@pytest.fixture
def native(fleet):
    c, _, sessions, _, _, _ = fleet
    with sessions.begin() as db:
        db.query(RuleSet).filter_by(policy_id="A").one().detectors = {
            "malicious_prompt": {"action": "block", "custom_malicious_detection": True}
        }
    enable(fleet)
    h, grant = credentials(fleet)
    classifier = Classifier()
    return c, h, sessions, grant, classifier, install_service(c, sessions, classifier)


@pytest.mark.parametrize("raw", [False, True])
def test_assessed_prompt_bound_replay_and_no_guard_side_effects(native, raw):
    c, h, sessions, grant, model, service = native
    with sessions.begin() as db:
        db.get(Policy, "A").raw_content_enabled = raw
    body = request_body()
    first = c.post(DECIDE, headers=h, json=body)
    assert first.status_code == 200, first.text
    reply = first.json()
    assert reply["grant_id"] == grant["grant_id"] and reply["grant_generation"] == grant["grant_generation"]
    assert reply["request_id"] == body["request_id"] and reply["occurrence_id"] == body["observation"]["occurrence_id"]
    assert reply["returned_action"] == reply["evaluated_action"] == "deny"
    assert reply["assessment"]["unsafe_score"] == 0.75
    assert reply["assessment"]["score_kind"] == "two_class_softmax_uncalibrated"
    assert first.headers["cache-control"] == "no-store"
    assert c.post(DECIDE, headers=h, json={**body, "budget_ms": 1700}).json() == reply
    for different in (
        {"prompt": PROMPT.strip()},
        {"request_id": str(uuid4())},
        {"observation": {**META, "occurrence_id": str(uuid4())}},
    ):
        assert c.post(DECIDE, headers=h, json={**body, **different}).json()["code"] == "identity_conflict"
    assert len(model.calls) == 1 and model.calls[0][0] == PROMPT
    next_reply = c.post(DECIDE, headers=h, json=request_body()).json()
    assert next_reply["decision_id"] != reply["decision_id"] and len(model.calls) == 2
    with sessions() as db:
        d = (
            db.execute(
                text("select * from native_prompt_decisions where decision_id=:id"), {"id": reply["decision_id"]}
            )
            .mappings()
            .one()
        )
        assert d["response_prepared"] and d["status"] == "committed"
        assert d["inference_request_id"] == str(model.calls[0][1])
        assert (
            len(
                {
                    d[k]
                    for k in (
                        "decision_id",
                        "event_id",
                        "owner_nonce",
                        "request_id",
                        "occurrence_id",
                        "inference_request_id",
                    )
                }
            )
            == 6
        )
        for table in ("native_prompt_assessments", "native_prompt_decisions", "native_prompt_observations"):
            rows = repr(db.execute(text("SELECT * FROM " + table)).all())
            assert PROMPT.strip() not in rows and hashlib.sha256(PROMPT.encode()).hexdigest() not in rows
            binding = service._binding((grant["device_id"], body["request_id"]))
            assert binding is not None and binding.digest.hex() not in rows and repr(binding.digest) not in rows
            assert service._key.hex() not in rows and repr(service._key) not in rows
    assert counts(sessions, AUDIT) == [0] * len(AUDIT)
    assert counts(sessions, ("native_prompt_decisions", "native_prompt_assessments", "native_prompt_observations")) == [
        2,
        2,
        3,
    ]


@pytest.mark.parametrize(
    "state, status, reason",
    [
        ("capture_disabled", "not_requested", "capture_disabled"),
        ("unsupported", "unsupported", "input_unsupported"),
        ("input_too_large", "unsupported", "input_too_large"),
    ],
)
def test_content_free_inputs_skip_model(native, state, status, reason):
    c, h, sessions, _, model, _ = native
    reply = c.post(DECIDE, headers=h, json=request_body(state)).json()
    assert reply["assessment"] == dict(status=status, reason=reason, profile="tidewall.prompt-injection.1")
    assert not model.calls and counts(sessions, AUDIT) == [0] * len(AUDIT)


def test_metadata_grant_and_malformed_body_do_not_admit_content(fleet):
    c, bearer, s, _, _, _ = fleet
    enable(fleet)
    model = Classifier()
    install_service(c, s, model)
    h, _ = credentials(fleet, False)
    for headers, body, code in [
        (bearer, request_body(), "unauthorized"),
        (h, request_body(), "unauthorized"),
        (h, {**request_body(), "unexpected": "synthetic-private"}, "invalid_request"),
        (h, request_body("unsupported"), "unauthorized"),
    ]:
        r = c.post(DECIDE, headers=headers, json=body)
        assert r.status_code >= 400 and r.json()["code"] == code
        assert set(r.json()) == {"request_id", "code", "version"} and len(r.content) <= 256
    assert not model.calls and counts(s, ("native_prompt_decisions", "native_prompt_observations")) == [0, 0]
    r = c.post(DECIDE, headers=h, json=request_body("capture_disabled"))
    assert r.json()["reason"] == "capture_disabled"


def test_independent_device_and_identical_ids(native, fleet):
    c, h, s, _, model, _ = native
    other_headers, principal = provision(s, str(uuid4()))
    h2, _ = credentials((c, other_headers, s, principal, fleet[4], fleet[5]))
    body = request_body()
    a, b = [c.post(DECIDE, headers=head, json=body).json() for head in (h, h2)]
    assert a["decision_id"] != b["decision_id"] and a["session_id"] != b["session_id"]
    assert len(model.calls) == 2


def test_late_delivery_bound_idempotent_and_no_action(native):
    c, h, s, grant, model, _ = native
    body = {**request_body(), "budget_ms": 350}
    reply = c.post(DECIDE, headers=h, json=body).json()
    time.sleep(0.36)
    assert c.post(DECIDE, headers=h, json={**body, "budget_ms": 1800}).json()["code"] == "request_retired"
    report = dict(
        report_id=str(uuid4()),
        decision_id=reply["decision_id"],
        request_id=reply["request_id"],
        occurrence_id=reply["occurrence_id"],
        evidence_source="controlled_observer",
        stage="effect_deny_no_effect_verified",
        tool_count=0,
        marker_present=False,
    )
    for _ in range(2):
        r = c.post(DELIVER, headers=h, json=report)
        assert r.json() == dict(version=1, report_id=report["report_id"], decision_id=reply["decision_id"])
    for changed in ({"tool_count": 1}, {"occurrence_id": str(uuid4())}, {"request_id": str(uuid4())}):
        assert c.post(DELIVER, headers=h, json={**report, **changed}).status_code >= 400
    assert len(model.calls) == 1 and counts(s, ("native_prompt_deliveries",)) == [1]
    with s.begin() as db:
        db.execute(
            text("UPDATE native_prompt_grants SET revoked_at=:now WHERE grant_id=:id"),
            {"id": grant["grant_id"], "now": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")},
        )
    assert c.post(DELIVER, headers=h, json=report).json()["code"] == "grant_revoked"


def test_decision_route_rejects_bad_request_before_writes(fleet):
    c, _, s, _, _, _ = fleet
    install_service(c, s, Classifier())
    enable(fleet)
    h, _ = credentials(fleet, False)
    r = c.post(DECIDE, headers=h, json={"prompt": "closed-input-sentinel"})
    assert r.status_code == 422
    assert r.json() == {"version": 1, "request_id": None, "code": "invalid_request"}
    assert counts(s, ("native_prompt_observations", "native_prompt_decisions")) == [0, 0]


@pytest.mark.parametrize(
    "kind,mode,reason,evaluated,prepared",
    [
        ("clean", False, "clean", "allow", "allow"),
        ("positive", True, "classifier_positive", "deny", "allow"),
        ("invalid", True, "classifier_invalid", "deny", "deny"),
        ("disabled", True, "classifier_unavailable", "deny", "deny"),
        ("token_limit", True, "input_too_large", "deny", "deny"),
    ],
)
def test_service_preserves_policy_outcome_and_optional_assessment(native, kind, mode, reason, evaluated, prepared):
    c, h, s, _, model, service = native
    with s.begin() as db:
        policy = db.get(Policy, "A")
        policy.report_only = mode
        policy.on_detector_failure = "block"
        policy.raw_content_enabled = True
    if kind == "disabled":
        service.classifier = None
    elif kind == "invalid":
        model.result = AssessmentResult("failed", "classifier_invalid")
    elif kind == "token_limit":
        model.result = AssessmentResult("unsupported", "input_too_large")
    elif kind == "clean":
        from dataclasses import replace

        model.result = replace(model.result, unsafe_score=0.1)
    r = c.post(DECIDE, headers=h, json=request_body()).json()
    assert (r["mode"], r["reason"], r["evaluated_action"], r["returned_action"]) == (
        "report" if mode else "enforce",
        reason,
        evaluated,
        prepared,
    )
    assert ("unsafe_score" in r["assessment"]) == (kind in ("clean", "positive"))
    assert len(model.calls) == int(kind != "disabled") and counts(s, AUDIT) == [0] * len(AUDIT)


def test_assessed_identity_is_never_substituted_for_the_pinned_identity(native):
    from dataclasses import replace

    c, h, s, _, model, _ = native
    model.result = replace(model.result, model_identity=replace(MODEL_IDENTITY, adapter_revision="0" * 40))
    reply = c.post(DECIDE, headers=h, json=request_body()).json()
    assert reply["assessment"] == dict(
        status="failed", reason="classifier_invalid", profile="tidewall.prompt-injection.1"
    )
    with s() as db:
        assert db.execute(text("select unsafe_score,model_identity from native_prompt_assessments")).one() == (
            None,
            None,
        )
