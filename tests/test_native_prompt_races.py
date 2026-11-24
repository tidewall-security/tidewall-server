import asyncio
import json
import threading
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import event, text

from app.auth.key_utils import hash_key
from app.db.models import AccessRule, GlobalPromptList, NativePromptDecision, Policy, RuleSet
from app.native_prompt import NativeError, NativePromptRequest
from app.services.native_prompt_grants import authorize_native
from tests import test_native_prompt_decisions as decisions
from tests.test_agent_event_ingest import counts
from tests.test_native_prompt_decisions import DECIDE, install_service, request_body
from tests.test_native_prompt_grants import CAP

native = decisions.native

fleet = decisions.fleet
store = decisions.store


def principal(native):
    _, h, s, _, _, _ = native
    with s() as db:
        return authorize_native(db, hash_key(h["Authorization"][7:]), hash_key(h[CAP]), now=datetime.now(UTC))


def change(s, kind):
    with s.begin() as db:
        db.execute(text("BEGIN IMMEDIATE"))
        rules = db.query(RuleSet).filter_by(policy_id="A").one()
        if kind == "policy":
            db.get(Policy, "A").report_only = True
        elif kind == "unsupported":
            rules.detectors = {"pii": {"enabled": True}}
        elif kind == "rule":
            db.add(
                AccessRule(
                    rule_set_id=rules.id,
                    name="new",
                    conditions={"field": "app_id", "op": "==", "value": "claude-code"},
                    then_action="block_and_stop",
                )
            )
        elif kind == "list":
            db.add(GlobalPromptList(list_type="malicious", pattern="synthetic", match_type="exact"))
        elif kind == "grant":
            db.execute(text("UPDATE native_prompt_grants SET revoked_at=CURRENT_TIMESTAMP"))
        elif kind == "expired":
            db.execute(
                text(
                    "UPDATE native_prompt_grants SET issued_at='2020-01-01 00:00:00.000000',"
                    "expires_at='2020-01-01 00:01:00.000000'"
                )
            )
        elif kind == "generation":
            db.execute(text("UPDATE native_prompt_policy_configs SET generation=generation+2"))
        elif kind == "access":
            db.execute(text("UPDATE access_tokens SET expires_at='2020-01-01 00:00:00.000000'"))
        elif kind == "device":
            db.execute(text("UPDATE devices SET status='revoked'"))
        elif kind == "nonce":
            db.execute(text("UPDATE native_prompt_decisions SET owner_nonce=:nonce"), {"nonce": str(uuid4())})


@pytest.mark.parametrize(
    "kind,code",
    [
        ("policy", "policy_changed"),
        ("rule", "policy_changed"),
        ("list", "policy_changed"),
        ("unsupported", "policy_unsupported"),
        ("grant", "grant_revoked"),
        ("generation", "grant_revoked"),
        ("expired", "grant_expired"),
        ("access", "unauthorized"),
        ("device", "unauthorized"),
        ("nonce", "request_retired"),
    ],
)
def test_other_writer_commits_while_provider_runs_and_suppresses_final_score(native, kind, code):
    c, h, s, _, model, _ = native

    async def during():
        await asyncio.to_thread(change, s, kind)

    model.during = during
    r = c.post(DECIDE, headers=h, json=request_body())
    assert r.json()["code"] == code
    assert len(model.calls) == 1 and counts(s, ("native_prompt_assessments",)) == [0]
    with s() as db:
        d = db.query(NativePromptDecision).one()
        assert d.returned_action is None and not d.response_prepared
        if kind != "nonce":
            assert d.status == "abandoned"


@pytest.mark.parametrize(
    "kind,code",
    [
        ("grant", "grant_revoked"),
        ("generation", "grant_revoked"),
        ("expired", "grant_expired"),
        ("access", "unauthorized"),
        ("device", "unauthorized"),
        ("unsupported", "policy_unsupported"),
    ],
)
def test_previously_authenticated_principal_is_checked_inside_admission(native, kind, code):
    _, _, s, _, model, service = native
    p = principal(native)
    change(s, kind)
    with pytest.raises(NativeError) as caught:
        asyncio.run(service.decide(NativePromptRequest(**request_body()), p, deadline=time.monotonic() + 1.8))
    assert caught.value.code == code and not model.calls and counts(s, ("native_prompt_decisions",)) == [0]


def test_duplicate_waiter_rechecks_and_never_redispatches(native):
    _, _, _, _, model, svc = native
    p = principal(native)
    req = NativePromptRequest(**request_body())

    async def run():
        started = asyncio.Event()
        finish = asyncio.Event()

        async def during():
            started.set()
            await finish.wait()

        model.during = during
        deadline = time.monotonic() + 1.8
        owner = asyncio.create_task(svc.decide(req, p, deadline=deadline))
        await asyncio.wait_for(started.wait(), 1)
        with pytest.raises(NativeError) as err:
            await svc.decide(req, p, deadline=time.monotonic() + 0.05)
        assert err.value.code == "deadline_exceeded" and not owner.done()
        duplicate = asyncio.create_task(svc.decide(req, p, deadline=deadline))
        finish.set()
        a, b = await asyncio.gather(owner, duplicate)
        assert a == b and len(model.calls) == 1 and model.calls[0][2] == deadline

    asyncio.run(run())


def test_restart_retires_pending_and_all_old_actionable_identities(native):
    c, h, s, _, model, service = native
    body = request_body()
    assert c.post(DECIDE, headers=h, json=body).status_code == 200
    other = request_body()
    another = c.post(DECIDE, headers=h, json=other).json()
    with s.begin() as db:
        db.execute(text("DELETE FROM native_prompt_assessments WHERE decision_id=:id"), {"id": another["decision_id"]})
        db.execute(
            text(
                "UPDATE native_prompt_decisions SET status='pending', evaluated_action=NULL,"
                "returned_action=NULL,reason=NULL,response_prepared=0 WHERE decision_id=:id"
            ),
            {"id": another["decision_id"]},
        )
    replacement = install_service(c, s, model)

    async def run():
        async with replacement.lifecycle():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=c.app), base_url="http://test") as client:
                for b in (body, other):
                    assert (await client.post(DECIDE, headers=h, json=b)).json()["code"] == "request_retired"

    asyncio.run(run())
    with s() as db:
        assert db.get(NativePromptDecision, another["decision_id"]).status == "abandoned"
    assert len(model.calls) == 2 and counts(s, ("native_prompt_assessments",)) == [1]


def test_busy_writer_and_elapsed_body_budget(native):
    c, h, s, _, model, _ = native
    with s.begin() as db:
        db.execute(text("BEGIN IMMEDIATE"))
        start = time.monotonic()
        r = c.post(DECIDE, headers=h, json={**request_body(), "budget_ms": 90})
        assert time.monotonic() - start < 0.6
        assert r.json()["code"] in ("storage_unavailable", "deadline_exceeded")

    def slow():
        time.sleep(0.12)
        yield json.dumps({**request_body(), "budget_ms": 70}).encode()

    assert (
        c.post(DECIDE, headers={**h, "content-type": "application/json"}, content=slow()).json()["code"]
        == "deadline_exceeded"
    )
    assert not model.calls and counts(s, ("native_prompt_decisions",)) == [0]


def test_cancelled_owner_and_cancellation_resistant_provider_cannot_publish(native):
    _, _, s, _, model, svc = native
    req = NativePromptRequest(**request_body())
    p = principal(native)

    async def run():
        entered = asyncio.Event()
        release = asyncio.Event()

        async def during():
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                await release.wait()

        model.during = during
        async with svc.lifecycle():
            owner = asyncio.create_task(svc.decide(req, p, deadline=time.monotonic() + 0.3))
            await asyncio.wait_for(entered.wait(), 1)
            owner.cancel()
            await asyncio.sleep(0.03)
            detached = owner.done()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await owner
            assert detached

    asyncio.run(run())
    with s() as db:
        d = db.query(NativePromptDecision).one()
        assert d.status == "abandoned" and d.returned_action is None
    assert counts(s, ("native_prompt_assessments",)) == [0]


def test_late_physical_commit_prepares_history_without_wire_action(native, monkeypatch):
    from types import SimpleNamespace

    from app.auth import middleware
    from app.routes import native_prompt
    from app.services import native_prompt_decisions

    c, h, sessions, _, model, _ = native
    engine = sessions.kw["bind"]
    body = {**request_body(), "budget_ms": 220}
    local = threading.local()
    now = time.monotonic()
    entered = threading.Event()
    completed = threading.Event()
    clock = SimpleNamespace(monotonic=lambda: now)
    for module in (middleware, native_prompt, native_prompt_decisions):
        monkeypatch.setattr(module, "time", clock)

    def marker(conn, cursor, statement, *args):
        if "insert into native_prompt_assessments" in statement.lower():
            local.final_commit = True

    commit = engine.dialect.do_commit

    def physical_commit(connection):
        nonlocal now
        if not getattr(local, "final_commit", False):
            return commit(connection)
        local.final_commit = False
        entered.set()
        now += 0.30
        commit(connection)
        completed.set()

    monkeypatch.setattr(engine.dialect, "do_commit", physical_commit)
    event.listen(engine, "before_cursor_execute", marker)

    async def run():
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        # The event loop and application share the controlled monotonic clock.
        # An independent real-time watchdog still bounds an unmet precondition.
        with monkeypatch.context() as patch:
            patch.setattr(loop, "time", clock.monotonic)
            watchdog = threading.Timer(10, lambda: loop.call_soon_threadsafe(task.cancel))
            watchdog.start()
            try:
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=c.app), base_url="http://test"
                ) as client:
                    r = await client.post(DECIDE, headers=h, json=body)
                    assert entered.is_set() and await asyncio.to_thread(completed.wait, 3)
                    assert r.status_code == 504 and r.json()["code"] == "deadline_exceeded"
                    assert "returned_action" not in r.json()
                    replay = await client.post(DECIDE, headers=h, json=body)
                    assert replay.json()["code"] == "request_retired"
                    assert "returned_action" not in replay.json()
            except asyncio.CancelledError:
                pytest.fail(f"commit watchdog: entered={entered.is_set()}, completed={completed.is_set()}")
            finally:
                watchdog.cancel()
                watchdog.join()

    try:
        asyncio.run(run())
        with sessions() as db:
            d = db.query(NativePromptDecision).one()
            assert (d.status, d.response_prepared, d.returned_action) == ("committed", True, "deny")
        assert counts(sessions, ("native_prompt_deliveries",)) == [0] and len(model.calls) == 1
    finally:
        event.remove(engine, "before_cursor_execute", marker)


def test_finalization_before_revocation_preserves_authorized_reply(native):
    c, h, s, _, model, _ = native
    req = request_body()
    reply = c.post(DECIDE, headers=h, json=req).json()
    change(s, "grant")
    assert reply["reason"] == "classifier_positive" and reply["returned_action"] == "deny"
    assert c.post(DECIDE, headers=h, json=req).json()["code"] == "grant_revoked"
    assert counts(s, ("native_prompt_assessments", "native_prompt_deliveries")) == [1, 0]


def test_decision_and_delivery_sql_are_worker_owned(native):
    c, h, s, _, _, _ = native
    eng = s.kw["bind"]
    threads = []

    def record(*args):
        threads.append(threading.get_ident())

    async def run():
        loop = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=c.app), base_url="http://test") as client:
            d = (await client.post(DECIDE, headers=h, json=request_body())).json()
            report = dict(
                report_id=str(uuid4()),
                stage="unknown",
                evidence_source="hook",
                **{k: d[k] for k in ("decision_id", "request_id", "occurrence_id")},
            )
            assert (await client.post("/v1/native-prompt/deliveries", headers=h, json=report)).status_code == 200
        assert threads and loop not in threads

    event.listen(eng, "before_cursor_execute", record)
    event.listen(eng, "commit", record)
    try:
        asyncio.run(run())
    finally:
        event.remove(eng, "before_cursor_execute", record)
        event.remove(eng, "commit", record)


def test_revocation_committed_after_reservation_before_dispatch(native, monkeypatch):
    from app.services import native_prompt_decisions as decisions

    c, h, s, _, model, _ = native
    real_check = decisions.evaluate_native_precheck

    def withdraw(snapshot, prompt):
        change(s, "grant")
        return real_check(snapshot, prompt)

    monkeypatch.setattr(decisions, "evaluate_native_precheck", withdraw)
    r = c.post(DECIDE, headers=h, json=request_body())
    assert r.json()["code"] == "grant_revoked" and not model.calls
    with s() as db:
        d = db.query(NativePromptDecision).one()
        assert (d.status, d.reason) == ("abandoned", "authority_changed")


def test_sql_worker_cancelled_before_commit_rolls_back_and_abandons(native):
    _, _, s, _, model, service = native
    p = principal(native)
    req = NativePromptRequest(**request_body())
    entered, release = threading.Event(), threading.Event()

    def block_flush(conn, cursor, statement, *args):
        if "insert into native_prompt_assessments" in statement.lower():
            entered.set()
            assert release.wait(2)

    async def run():
        async with service.lifecycle():
            task = asyncio.create_task(service.decide(req, p, deadline=time.monotonic() + 1.8))
            assert await asyncio.to_thread(entered.wait, 1)
            task.cancel()
            await asyncio.sleep(0.02)
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task

    engine = s.kw["bind"]
    event.listen(engine, "before_cursor_execute", block_flush)
    try:
        asyncio.run(run())
    finally:
        release.set()
        event.remove(engine, "before_cursor_execute", block_flush)
    assert len(model.calls) == 1 and counts(s, ("native_prompt_assessments",)) == [0]
    with s() as db:
        assert db.query(NativePromptDecision).one().status == "abandoned"


def test_cancel_during_physical_commit_keeps_prepared_history_ineligible_for_replay(native):
    _, _, s, _, _, service = native
    p = principal(native)
    req = NativePromptRequest(**request_body())
    entered, release = threading.Event(), threading.Event()

    def mark(conn, cursor, statement, *args):
        if "insert into native_prompt_assessments" in statement.lower():
            conn.info["physical_commit_test"] = True

    def block(conn):
        if conn.info.pop("physical_commit_test", False):
            entered.set()
            assert release.wait(2)

    async def run():
        async with service.lifecycle():
            deadline = time.monotonic() + 1.8
            task = asyncio.create_task(service.decide(req, p, deadline=deadline))
            assert await asyncio.to_thread(entered.wait, 1)
            task.cancel()
            await asyncio.sleep(0.02)
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
            with pytest.raises(NativeError) as error:
                await service.decide(req, p, deadline=deadline)
            assert error.value.code == "request_retired"

    eng = s.kw["bind"]
    event.listen(eng, "before_cursor_execute", mark)
    event.listen(eng, "commit", block)
    try:
        asyncio.run(run())
    finally:
        release.set()
        event.remove(eng, "before_cursor_execute", mark)
        event.remove(eng, "commit", block)
    assert counts(s, ("native_prompt_assessments", "native_prompt_deliveries")) == [1, 0]


def test_asgi_disconnect_before_provider_completion_abandons(native):
    c, h, s, _, model, service = native

    async def run():
        entered = asyncio.Event()

        async def during():
            entered.set()
            await asyncio.Future()

        model.during = during
        body = json.dumps(request_body()).encode()
        initial = True

        async def receive():
            nonlocal initial
            if initial:
                initial = False
                return {"type": "http.request", "body": body, "more_body": False}
            await entered.wait()
            return {"type": "http.disconnect"}

        sent = []

        async def send(message):
            sent.append(message)

        async with service.lifecycle():
            await asyncio.wait_for(
                c.app(
                    {
                        "type": "http",
                        "asgi": {"version": "3.0"},
                        "http_version": "1.1",
                        "method": "POST",
                        "scheme": "http",
                        "path": DECIDE,
                        "raw_path": DECIDE.encode(),
                        "query_string": b"",
                        "client": ("127.0.0.1", 8090),
                        "server": ("test", 80),
                        "headers": [
                            (k.lower().encode(), v.encode())
                            for k, v in {**h, "content-type": "application/json"}.items()
                        ],
                    },
                    receive,
                    send,
                ),
                1.5,
            )
        assert all(msg.get("status") != 200 and b"returned_action" not in msg.get("body", b"") for msg in sent)

    asyncio.run(run())
    assert len(model.calls) == 1 and counts(s, ("native_prompt_assessments",)) == [0]
    with s() as db:
        assert db.query(NativePromptDecision).one().status == "abandoned"


def test_lost_response_can_replay_only_timely_under_live_policy(native):
    from fastapi.testclient import TestClient

    c, h, s, _, model, _ = native

    class LostResponse:
        async def __call__(self, scope, receive, send):
            async def drop(message):
                if message["type"] == "http.response.start":
                    raise ConnectionResetError("lost synthetic reply")
                await send(message)

            await c.app(scope, receive, drop)

    b = request_body()
    with pytest.raises(ConnectionResetError):
        TestClient(LostResponse()).post(DECIDE, headers=h, json=b)
    assert c.post(DECIDE, headers=h, json=b).json()["returned_action"] == "deny"
    change(s, "policy")
    assert c.post(DECIDE, headers=h, json=b).json()["code"] == "policy_changed"
    assert len(model.calls) == 1 and counts(s, ("native_prompt_assessments", "native_prompt_deliveries")) == [1, 0]


def test_provider_that_ignores_timeout_cannot_finalize_a_late_score(native):
    _, _, s, _, model, service = native
    p = principal(native)
    req = NativePromptRequest(**request_body())

    async def run():
        arrived = asyncio.Event()
        release = asyncio.Event()

        async def waiting():
            arrived.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                await release.wait()

        model.during = waiting
        async with service.lifecycle():
            deadline = time.monotonic() + 0.25
            task = asyncio.create_task(service.decide(req, p, deadline=deadline))
            await asyncio.wait_for(arrived.wait(), 0.2)
            with pytest.raises(NativeError) as error:
                await asyncio.wait_for(task, 0.5)
            assert error.value.code == "deadline_exceeded"
            release.set()

    asyncio.run(run())
    with s() as db:
        assert db.query(NativePromptDecision).one().status == "abandoned"
    assert counts(s, ("native_prompt_assessments", "native_prompt_deliveries")) == [0, 0]


def test_replay_response_serialization_cannot_extend_owner_output_budget(native, monkeypatch):
    from app.routes.native_prompt import JSONResponse

    c, h, _, _, _, _ = native
    req = {**request_body(), "budget_ms": 250}
    assert c.post(DECIDE, headers=h, json=req).status_code == 200
    prepare = JSONResponse.render

    def slow(self, content):
        if isinstance(content, dict) and "returned_action" in content:
            time.sleep(0.27)
        return prepare(self, content)

    monkeypatch.setattr(JSONResponse, "render", slow)
    r = c.post(DECIDE, headers=h, json={**req, "budget_ms": 1800})
    assert r.json()["code"] == "deadline_exceeded"


def test_prepared_finalization_can_win_concurrent_revocation(native):
    from concurrent.futures import ThreadPoolExecutor

    c, h, s, _, model, _ = native
    eng = s.kw["bind"]
    prepared, withdrawn = threading.Event(), threading.Event()

    def intercept(conn, cursor, statement, *args):
        if "insert into native_prompt_assessments" in statement.lower():
            prepared.set()
            assert withdrawn.wait(1)

    event.listen(eng, "before_cursor_execute", intercept)
    try:
        with ThreadPoolExecutor(2) as executor:

            def revoke():
                assert prepared.wait(1)
                withdrawn.set()
                change(s, "grant")

            other = executor.submit(revoke)
            req = request_body()
            r = c.post(DECIDE, headers=h, json=req)
            other.result(1)
        assert r.json()["returned_action"] == "deny"
        assert c.post(DECIDE, headers=h, json=req).json()["code"] == "grant_revoked"
        assert counts(s, ("native_prompt_assessments", "native_prompt_deliveries")) == [1, 0] and len(model.calls) == 1
    finally:
        event.remove(eng, "before_cursor_execute", intercept)


def test_registry_caps_current_process_bindings_and_reclaims_idle_entries(native):
    import weakref

    from app.services.native_prompt_decisions import _Budget, _Owner

    _, _, s, _, _, service = native
    p = principal(native)

    async def run():
        async with service.lifecycle():
            deadline = time.monotonic() + 1.8
            requests = [NativePromptRequest(**request_body()) for _ in range(1025)]
            for req in requests[:-1]:
                owner = _Owner(deadline)
                service._register((p.device_id, req.request_id), owner, weakref.ref(req), _Budget(deadline))
                assert not hasattr(owner, "prompt")
            with pytest.raises(NativeError) as err:
                await service.decide(requests[-1], p, deadline=deadline)
            assert err.value.code == "capacity"
            await asyncio.sleep(5.1)
            assert not service._bindings
            result = await service.decide(requests[-1], p, deadline=time.monotonic() + 1.8)
            assert result.returned_action == "deny"

    asyncio.run(run())
    assert counts(s, ("native_prompt_decisions",)) == [1]


def test_revoked_replay_cannot_probe_content_binding_or_delay_revocation_until_owner_finishes(native):
    _, _, s, _, model, svc = native
    p = principal(native)
    req = NativePromptRequest(**request_body())

    async def run():
        entered, release = asyncio.Event(), asyncio.Event()

        async def wait():
            entered.set()
            await release.wait()

        model.during = wait
        task = asyncio.create_task(svc.decide(req, p, deadline=time.monotonic() + 1.8))
        try:
            await asyncio.wait_for(entered.wait(), 1)
            await asyncio.to_thread(change, s, "grant")
            for dup in (req.model_copy(update={"prompt": "different synthetic prompt"}), req):
                with pytest.raises(NativeError) as error:
                    await svc.decide(dup, p, deadline=time.monotonic() + 0.25)
                assert error.value.code == "grant_revoked"
        finally:
            release.set()
            with pytest.raises(NativeError):
                await task

    asyncio.run(run())
    assert len(model.calls) == 1 and counts(s, ("native_prompt_assessments",)) == [0]


@pytest.mark.parametrize("when", ["before_admission", "after_dispatch"])
def test_recovered_device_cannot_inherit_request_or_session_secret(native, when):
    from app.db.models import Device
    from app.services.device_service import DeviceService

    c, h, s, _, model, svc = native
    old = principal(native)
    req = NativePromptRequest(**request_body())

    def recover():
        with s() as db:
            devices = DeviceService(db, actor_policy_id="A")
            device = db.get(Device, old.device_id)
            installation = device.installation_id
            devices.update_device_status(old.device_id, "revoked")
            devices.delete_device(old.device_id)
            secret = devices.authorise_recovery(old.device_id)
            key, _ = devices.create_registration_token(
                "controlled recovery", "A", purpose="collector_write", expires_at=datetime.now(UTC) + timedelta(hours=1)
            )
            replacement = devices.enrol_device(
                hash_key(key), installation, "controlled", "", "", "native", "synthetic", "1", recovery_secret=secret
            )["result"]
            assert replacement["device_id"] != old.device_id
            devices.approve_device(replacement["device_id"], replacement["confirmation_code"])
            return replacement["access_token"]["token"]

    async def run():
        replacement = []

        async def swap():
            replacement.append(await asyncio.to_thread(recover))

        if when == "before_admission":
            await swap()
        else:
            model.during = swap
        with pytest.raises(NativeError) as error:
            await svc.decide(req, old, deadline=time.monotonic() + 1.8)
        assert error.value.code == "unauthorized"
        return replacement[0]

    bearer = asyncio.run(run())
    r = c.post(DECIDE, headers={**h, "Authorization": "Bearer " + bearer}, json=req.model_dump())
    assert r.json()["code"] == "unauthorized"
    assert len(model.calls) == int(when == "after_dispatch")
    assert counts(s, ("native_prompt_decisions", "native_prompt_assessments", "native_prompt_deliveries")) == [0, 0, 0]


def test_config_aba_and_reissued_grant_do_not_resurrect_old_decision(native, fleet):
    from tests.test_native_prompt_grants import CFG, issue

    c, h, s, _, model, _ = native
    req = request_body()
    a = c.post(DECIDE, headers=h, json=req).json()
    for threshold in (0.8, 0.5):
        assert c.put(CFG, headers=fleet[5], json=dict(enabled=True, threshold=threshold)).status_code == 200
    assert c.post(DECIDE, headers=h, json=req).json()["code"] == "grant_revoked"
    new = issue(fleet, capture_allowed=True, session_id=a["session_id"]).json()
    h2 = {**h, CAP: new["capability"]}
    assert c.post(DECIDE, headers=h2, json=req).json()["code"] == "identity_conflict"
    b = c.post(DECIDE, headers=h2, json=request_body()).json()
    assert b["grant_generation"] > a["grant_generation"] and b["policy_revision"] == a["policy_revision"]
    assert len(model.calls) == 2 and counts(s, ("native_prompt_assessments",)) == [2]


def test_fresh_rule_at_admission_blocks_before_model_even_with_capture_disabled(native):
    c, h, s, _, model, _ = native
    change(s, "rule")
    for state in ("capture_disabled", "complete"):
        reply = c.post(DECIDE, headers=h, json=request_body(state)).json()
        assert reply["reason"] == "access_rule_block" and reply["returned_action"] == "deny"
        assert reply["assessment"]["status"] == "not_requested"
    assert not model.calls and counts(s, ("interactions", "interaction_contents", "content_export_attempts")) == [
        0,
        0,
        0,
    ]


def test_owner_cannot_send_prepared_reply_if_disconnect_cleanup_crosses_output_budget(native, monkeypatch):
    from app.routes import native_prompt

    c, h, s, _, _, _ = native

    async def delayed_cleanup(request):
        try:
            await asyncio.Future()
        finally:
            await asyncio.sleep(0.28)

    monkeypatch.setattr(native_prompt, "_disconnected", delayed_cleanup)
    r = c.post(DECIDE, headers=h, json={**request_body(), "budget_ms": 210})
    assert r.json()["code"] == "deadline_exceeded"
    assert counts(s, ("native_prompt_assessments", "native_prompt_deliveries")) == [1, 0]


@pytest.mark.parametrize("replay", [False, True])
def test_outer_middleware_cannot_forward_expired_owner_or_replay(native, monkeypatch, replay):
    from app.security_headers import SecurityHeadersMiddleware

    c, h, sessions, _, model, _ = native
    original = {**request_body(), "budget_ms": 350}
    if replay:
        assert c.post(DECIDE, headers=h, json=original).status_code == 200
    # Fixture provisioning has already built the actual stack, whose middleware
    # captures its dispatch function at construction.
    middleware = c.app.middleware_stack
    while not isinstance(middleware, SecurityHeadersMiddleware):
        middleware = middleware.app
    old_dispatch = middleware.dispatch_func
    exercised = []

    async def delayed(request, call_next):
        response = await old_dispatch(request, call_next)
        if request.url.path == DECIDE:
            assert response.status_code == 200
            exercised.append(True)
            await asyncio.sleep(0.38)
        return response

    monkeypatch.setattr(middleware, "dispatch_func", delayed)
    result = c.post(
        DECIDE, headers={**h, "Origin": "http://local.test"}, json={**original, "budget_ms": 1800 if replay else 350}
    )
    assert exercised == [True]
    assert result.status_code == 504
    assert result.json() == {"version": 1, "request_id": original["request_id"], "code": "deadline_exceeded"}
    assert result.headers["cache-control"] == "no-store" and result.headers["x-frame-options"] == "DENY"
    assert result.headers["access-control-allow-origin"] == "*"
    assert len(result.content) == int(result.headers["content-length"])
    assert len(model.calls) == 1 and counts(sessions, ("native_prompt_assessments", "native_prompt_deliveries")) == [
        1,
        0,
    ]


def test_slow_transport_after_accepting_headers_cannot_receive_late_directive(native):
    c, h, s, _, _, _ = native

    async def run():
        body = json.dumps({**request_body(), "budget_ms": 250}).encode()
        first = True

        async def receive():
            nonlocal first
            if first:
                first = False
                return {"type": "http.request", "body": body, "more_body": False}
            await asyncio.Future()

        sent = []

        async def send(message):
            sent.append(message)
            if message["type"] == "http.response.start":
                await asyncio.sleep(0.30)

        await c.app(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": DECIDE,
                "raw_path": DECIDE.encode(),
                "query_string": b"",
                "client": ("127.0.0.1", 8090),
                "server": ("test", 80),
                "headers": [
                    (k.lower().encode(), v.encode()) for k, v in {**h, "content-type": "application/json"}.items()
                ],
            },
            receive,
            send,
        )
        assert [m["status"] for m in sent if m["type"] == "http.response.start"] == [200]
        assert b"".join(m.get("body", b"") for m in sent) == b""

    asyncio.run(run())
    assert counts(s, ("native_prompt_assessments", "native_prompt_deliveries")) == [1, 0]


@pytest.mark.parametrize("blocked", ["executor", "connection"])
def test_expired_admission_releases_synthetic_prompt_while_worker_still_blocked(native, blocked):
    import weakref
    from concurrent.futures import ThreadPoolExecutor

    _, _, s, _, model, svc = native
    p = principal(native)
    release = threading.Event()
    entered = threading.Event()

    def occupy(*args):
        entered.set()
        assert release.wait(3)

    class SyntheticText(str):
        pass

    async def run():
        loop = asyncio.get_running_loop()
        engine = s.kw["bind"]
        if blocked == "executor":
            loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
            occupied = loop.run_in_executor(None, occupy)
        else:
            event.listen(engine, "checkout", occupy)
        try:
            prompt = SyntheticText("temporary synthetic data")
            req = NativePromptRequest(**request_body()).model_copy(update={"prompt": prompt})
            prompt_ref, request_ref = weakref.ref(prompt), weakref.ref(req)
            try:
                await svc.decide(req, p, deadline=time.monotonic() + 0.10)
            except NativeError as error:
                assert error.code == "deadline_exceeded"
            else:
                pytest.fail("occupied worker returned a decision")
            assert entered.is_set()
            del req, prompt
            assert request_ref() is None and prompt_ref() is None
            assert not model.calls
        finally:
            release.set()
            if blocked == "executor":
                await occupied
            else:
                # Removal is safe once the originating checkout has returned.
                await asyncio.gather(*list(svc._tasks), return_exceptions=True)
                event.remove(engine, "checkout", occupy)

    asyncio.run(run())
    assert counts(s, ("native_prompt_decisions", "native_prompt_assessments")) == [0, 0]


def test_saturated_native_admission_refuses_new_work_until_queued_units_finish(native, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    from app.services import native_prompt_decisions as module

    c, _, s, _, model, _ = native
    p = principal(native)
    monkeypatch.setattr(module, "_MAX_BINDINGS", 2)
    svc = install_service(c, s, model)
    release = threading.Event()

    async def run():
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        occupied = loop.run_in_executor(None, release.wait, 3)

        async def attempt(seconds):
            try:
                await svc.decide(NativePromptRequest(**request_body()), p, deadline=time.monotonic() + seconds)
            except NativeError as err:
                return err.code
            return "ok"

        try:
            first, second = [asyncio.create_task(attempt(0.12)) for _ in range(2)]
            await asyncio.sleep(0.02)
            assert await attempt(0.04) == "capacity"
            assert await asyncio.gather(first, second) == ["deadline_exceeded", "deadline_exceeded"]
            assert await attempt(0.05) == "capacity"
            assert not model.calls
        finally:
            release.set()
            await occupied
        await asyncio.gather(*list(svc._tasks), return_exceptions=True)
        await asyncio.sleep(0)
        assert await attempt(1) == "ok"

    asyncio.run(run())
    assert len(model.calls) == 1 and counts(s, ("native_prompt_decisions",)) == [1]


def test_saturated_http_callback_is_refused_before_consuming_prompt_body(native, monkeypatch):
    from app.services import native_prompt_decisions as module

    c, h, s, _, model, _ = native
    monkeypatch.setattr(module, "_MAX_BINDINGS", 1)
    svc = install_service(c, s, model)

    async def run():
        reads = []

        async def receive():
            reads.append(True)
            return {"type": "http.request", "body": b"malformed synthetic prompt", "more_body": False}

        sent = []

        async def send(message):
            sent.append(message)

        with svc.admission():
            await c.app(
                {
                    "type": "http",
                    "asgi": {"version": "3.0"},
                    "http_version": "1.1",
                    "method": "POST",
                    "scheme": "http",
                    "path": DECIDE,
                    "raw_path": DECIDE.encode(),
                    "query_string": b"",
                    "client": ("127.0.0.1", 8090),
                    "server": ("test", 80),
                    "headers": [
                        (k.lower().encode(), v.encode()) for k, v in {**h, "content-type": "application/json"}.items()
                    ],
                },
                receive,
                send,
            )
        assert not reads
        assert json.loads(b"".join(m.get("body", b"") for m in sent)) == dict(
            version=1, request_id=None, code="capacity"
        )

    asyncio.run(run())
    assert not model.calls and counts(s, ("native_prompt_decisions",)) == [0]


@pytest.mark.parametrize("blocked", ["executor", "checkout", "writer"])
def test_contended_replay_cannot_wait_past_known_owner_deadline(native, blocked):
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import ExitStack

    _, _, sessions, _, model, service = native
    principal_ = principal(native)
    request = NativePromptRequest(**request_body())
    release = threading.Event()
    started = threading.Event()

    def hold(*args):
        started.set()
        assert release.wait(3)

    async def run():
        owner_deadline = time.monotonic() + 0.42
        original = await service.decide(request, principal_, deadline=owner_deadline)
        assert original.returned_action == "deny"
        loop = asyncio.get_running_loop()
        engine = sessions.kw["bind"]
        with ExitStack() as cleanup:
            if blocked == "executor":
                loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
                occupied = loop.run_in_executor(None, hold)
            elif blocked == "checkout":
                event.listen(engine, "checkout", hold)
                cleanup.callback(event.remove, engine, "checkout", hold)
            else:
                db = cleanup.enter_context(sessions.begin())
                db.execute(text("BEGIN IMMEDIATE"))

            async def replay():
                try:
                    await service.decide(request, principal_, deadline=time.monotonic() + 1.8)
                except NativeError as error:
                    return error.code, time.monotonic()
                pytest.fail("contended duplicate returned a directive")

            task = asyncio.create_task(replay())
            try:
                # A later 1.8 s request still has an occupied executor/checkout or
                # SQLite writer when the original 420 ms budget expires.
                done, _ = await asyncio.wait({task}, timeout=max(0, owner_deadline - time.monotonic()) + 0.12)
                assert task in done
                code, finished = task.result()
                assert finished <= owner_deadline + 0.12 and code in ("deadline_exceeded", "storage_unavailable")
                if blocked != "writer":
                    assert started.is_set() and code == "deadline_exceeded"
            finally:
                release.set()
                if blocked == "executor":
                    await occupied
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                if blocked != "writer":
                    await asyncio.gather(*list(service._tasks), return_exceptions=True)

    asyncio.run(run())
    assert len(model.calls) == 1 and counts(sessions, ("native_prompt_assessments", "native_prompt_decisions")) == [
        1,
        1,
    ]


def _inspect_native_queue(service, req, monkeypatch):
    import dataclasses
    import hmac

    submitted = asyncio.Event()
    digest = hmac.digest(service._key, req.model_dump_json(exclude={"budget_ms"}).encode(), "sha256")
    submit = asyncio.to_thread
    inspected = []
    leaked = []

    def carries_content(value):
        if isinstance(value, NativePromptRequest):
            return True
        if isinstance(value, bytes):
            return len(value) == 32 or digest in value or req.prompt.encode() in value
        if isinstance(value, str):
            return req.prompt in value or digest.hex() in value
        if dataclasses.is_dataclass(value):
            return any(carries_content(getattr(value, f.name)) for f in dataclasses.fields(value))
        if isinstance(value, tuple | list):
            return any(carries_content(item) for item in value)
        if isinstance(value, dict):
            return any(carries_content(item) for item in value.values())
        return False

    async def inspect_queue(func, *args, **kwargs):
        if getattr(func, "__self__", None) is service:
            submitted.set()
            inspected.append(func.__name__)
            if carries_content(args):
                leaked.append(func.__name__)
        return await submit(func, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", inspect_queue)

    return submitted, inspected, leaked


def test_full_registry_never_hashes_a_queued_or_over_capacity_new_admission(native, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    from app.services import native_prompt_decisions as module

    c, _, sessions, _, model, _ = native
    principal_ = principal(native)
    monkeypatch.setattr(module, "_MAX_BINDINGS", 2)
    service = install_service(c, sessions, model)
    new = NativePromptRequest(**{**request_body(), "prompt": "SyntheticFullRegistryMarker"})
    original_hash = module.hmac.digest
    hashes = []

    def hash_spy(key, msg, digest):
        if new.prompt.encode() in msg:
            hashes.append(True)
        return original_hash(key, msg, digest)

    release = threading.Event()

    async def run():
        for _ in range(2):
            await service.decide(NativePromptRequest(**request_body()), principal_, deadline=time.monotonic() + 1.8)
        assert len(service._bindings) == 2
        submitted, inspected, leaked = _inspect_native_queue(service, new, monkeypatch)
        monkeypatch.setattr(module.hmac, "digest", hash_spy)
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        occupied = loop.run_in_executor(None, release.wait, 3)

        async def attempt():
            with pytest.raises(NativeError) as error:
                await service.decide(new, principal_, deadline=time.monotonic() + 1.4)
            return error.value.code

        task = asyncio.create_task(attempt())
        try:
            await asyncio.wait_for(submitted.wait(), 0.4)
            assert inspected == ["_admit"] and not leaked
            assert not task.done() and not hashes
        finally:
            release.set()
            await occupied
            code = await task
        assert code == "capacity" and len(service._bindings) == 2 and not hashes

    asyncio.run(run())
    assert len(model.calls) == 2 and counts(sessions, ("native_prompt_assessments", "native_prompt_decisions")) == [
        2,
        2,
    ]


def test_db_worker_arguments_never_include_raw_or_keyed_content(native, monkeypatch):
    _, _, sessions, _, model, service = native
    principal_ = principal(native)
    req = NativePromptRequest(**{**request_body(), "prompt": "SyntheticQueueMarker"})
    _, inspected, leaked = _inspect_native_queue(service, req, monkeypatch)

    async def run():
        one = await service.decide(req, principal_, deadline=time.monotonic() + 1.8)
        two = await service.decide(req, principal_, deadline=time.monotonic() + 1.8)
        assert one == two

        async def edit_policy():
            await asyncio.to_thread(change, sessions, "policy")

        model.during = edit_policy
        later = NativePromptRequest(**{**request_body(), "prompt": req.prompt})
        with pytest.raises(NativeError) as error:
            await service.decide(later, principal_, deadline=time.monotonic() + 1.8)
        assert error.value.code == "policy_changed"

    asyncio.run(run())
    assert {"_admit", "_dispatch_check", "_finalize", "_abandon"} <= set(inspected)
    assert not leaked
    assert len(model.calls) == 2 and counts(sessions, ("native_prompt_assessments",)) == [1]
