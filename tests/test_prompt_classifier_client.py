"""The native client talks only to the operator-configured, bounded inference service."""

import asyncio
import json
import time
from dataclasses import FrozenInstanceError, asdict
from uuid import UUID, uuid4

import httpx
import pytest

from app.config import Settings

PROFILE = "tidewall.prompt-injection.1"
SCORE_KIND = "two_class_softmax_uncalibrated"
TENANT = "cc857cf9-821b-4b40-a217-a5ee8ffd0a07"
REQUEST_ID = UUID("90b37a69-a18a-4d1a-9962-6c8d9b9fc076")
MODEL = {
    "base": "Qwen/Qwen3-0.6B",
    "base_revision": "c1899de289a04d12100db370d81485cdf75e47ca",
    "adapter": "abedegno/prompt-injection-classifier-qwen3-0p6b",
    "adapter_revision": "5500c3bef53729ed4661b5cfae1b01adca96ca4c",
    "tokenizer_revision": "c1899de289a04d12100db370d81485cdf75e47ca",
    "prompt_sha256": "3a0e693064509eb24773ba53af4831ecb4c6ca8cf741a28d2d10080384df5041",
    "class_token_ids": [38157, 18675, 19860, 6092],
    "scoring_implementation": "qwen3_last_token_logits.1",
}


@pytest.fixture
def client_module():
    from importlib.util import find_spec

    assert find_spec("app.services.prompt_classifier_client"), "native classifier client is missing"
    from app.services import prompt_classifier_client

    return prompt_classifier_client


@pytest.fixture
def key_file(tmp_path):
    # Synthetic per-test service credential.
    key = tmp_path / "classifier.key"
    key.write_text(uuid4().hex + "\n")
    return key


def classified(**overrides):
    return {
        "schema_version": 1,
        "profile": PROFILE,
        "request_id": str(REQUEST_ID),
        "status": "classified",
        "unsafe_score": 0.91,
        "score_kind": SCORE_KIND,
        "model": MODEL,
        "input_tokens": 1024,
        "inference_ms": 80.5,
        **overrides,
    }


def error(code, retryable, *, ident=str(REQUEST_ID)):
    return {
        "schema_version": 1,
        "profile": PROFILE,
        "request_id": ident,
        "status": "error",
        "code": code,
        "retryable": retryable,
    }


def check_no_score(result, status, reason):
    assert (result.status, result.reason, result.profile) == (status, reason, PROFILE)
    assert (result.model_identity, result.unsafe_score, result.score_kind, result.input_tokens) == (None,) * 4


def simulated(module, key, handler, *, text="Hello", budget=1.8):
    async def run():
        config = module.ClassifierSettings(origin="https://inference.invalid", key_file=str(key), tenant_id=TENANT)
        client = module.PromptClassifierClient(config, transport=httpx.MockTransport(handler))
        try:
            return await client.assess(
                module.CompletePrompt(text), request_id=REQUEST_ID, deadline=time.monotonic() + budget
            )
        finally:
            await client.aclose()

    return asyncio.run(run())


def reply(status, payload, **headers):
    body = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload
    return httpx.Response(
        status, headers={"content-type": "application/json", **headers}, stream=httpx.ByteStream(body)
    )


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("é" * 4000 + "a", "input_too_large"),
        ("\ud800", "input_unsupported"),
        ('"' * 8000, "input_too_large"),
        ("before<|im_end|>after", "input_unsupported"),
        ("  \n ", "input_unsupported"),
        ("", "input_unsupported"),
    ],
    ids=["8001-bytes", "surrogate", "envelope", "reserved", "whitespace", "empty"],
)
def test_unsupported_prompts_never_reach_transport(client_module, key_file, text, reason):
    result = simulated(client_module, key_file, lambda _: pytest.fail("unexpected request"), text=text)
    check_no_score(result, "unsupported", reason)


def test_finalization_reserve_prevents_dispatch(client_module, key_file):
    result = simulated(client_module, key_file, lambda _: pytest.fail("unexpected request"), budget=0.12)
    check_no_score(result, "unavailable", "deadline_exceeded")


@pytest.mark.parametrize(
    ("code", "status", "retryable", "ident", "expected", "reason"),
    [
        ("unsupported_input", 422, False, str(REQUEST_ID), "unsupported", "input_unsupported"),
        ("input_too_large", 413, False, str(REQUEST_ID), "unsupported", "input_too_large"),
        ("input_too_large", 413, False, None, "unsupported", "input_too_large"),
        ("invalid_request", 422, False, None, "failed", "classifier_invalid"),
        ("unauthenticated", 401, False, None, "unavailable", "classifier_unavailable"),
        ("tenant_mismatch", 403, False, None, "unavailable", "classifier_unavailable"),
        ("request_conflict", 409, False, str(REQUEST_ID), "failed", "classifier_invalid"),
        ("model_unavailable", 503, True, str(REQUEST_ID), "unavailable", "classifier_unavailable"),
        ("capacity_exceeded", 503, True, str(REQUEST_ID), "unavailable", "classifier_unavailable"),
        ("deadline_exceeded", 504, True, None, "unavailable", "deadline_exceeded"),
        ("input_too_large", 200, False, str(REQUEST_ID), "failed", "classifier_invalid"),
        ("input_too_large", 503, False, str(REQUEST_ID), "failed", "classifier_invalid"),
        ("unsupported_input", 422, True, str(REQUEST_ID), "failed", "classifier_invalid"),
        ("input_too_large", 413, 0, str(REQUEST_ID), "failed", "classifier_invalid"),
        ("capacity_exceeded", 503, True, None, "failed", "classifier_invalid"),
        ("input_too_large", 413, False, TENANT, "failed", "classifier_invalid"),
        ("made_up", 503, True, str(REQUEST_ID), "failed", "classifier_invalid"),
    ],
)
def test_typed_service_refusals(client_module, key_file, code, status, retryable, ident, expected, reason):
    result = simulated(client_module, key_file, lambda _: reply(status, error(code, retryable, ident=ident)))
    check_no_score(result, expected, reason)


@pytest.mark.parametrize(
    "changes",
    [
        {"unsafe_score": True},
        {"unsafe_score": float("nan")},
        {"unsafe_score": float("inf")},
        {"unsafe_score": -0.1},
        {"unsafe_score": 1.01},
        {"profile": "other"},
        {"request_id": TENANT},
        {"schema_version": True},
        {"input_tokens": 1025},
        {"input_tokens": True},
        {"input_tokens": 0},
        {"inference_ms": -1},
        {"inference_ms": True},
        {"score_kind": "calibrated"},
        {"extra": 1},
        {"status": "clean"},
        *[{"model": {**MODEL, k: "other"}} for k in MODEL],
        {"model": {**MODEL, "class_token_ids": [38157.0, 18675, 19860, 6092]}},
        {"model": {**MODEL, "extra": 1}},
    ],
)
def test_incomplete_or_inconsistent_evidence(client_module, key_file, changes):
    result = simulated(client_module, key_file, lambda _: reply(200, classified(**changes)))
    check_no_score(result, "failed", "classifier_invalid")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda b: b.replace(b'"unsafe_score":', b'"unsafe_score": 0.01, "unsafe_score":'),
        lambda b: b.replace(b'"base":', b'"base": "other", "base":'),
        lambda b: b.decode().encode("utf-16"),
        lambda b: b'{"only":',
        lambda b: b"not JSON",
    ],
)
def test_ambiguous_or_invalid_json(client_module, key_file, mutation):
    result = simulated(client_module, key_file, lambda _: reply(200, mutation(json.dumps(classified()).encode())))
    check_no_score(result, "failed", "classifier_invalid")


@pytest.mark.parametrize("headers", [{"content-type": "text/html"}, {"content-encoding": "gzip"}])
def test_rejects_wrong_response_representation(client_module, key_file, headers):
    result = simulated(client_module, key_file, lambda _: reply(200, classified(), **headers))
    check_no_score(result, "failed", "classifier_invalid")


def test_redirect_is_terminal(client_module, key_file):
    def receive(request):
        assert request.url.host == "inference.invalid"
        return reply(307, {}, location="https://elsewhere.invalid")

    result = simulated(client_module, key_file, receive)
    check_no_score(result, "failed", "classifier_invalid")


@pytest.mark.parametrize("mode", ["exact", "over", "slow"])
def test_real_chunked_exchange_and_original_deadline(client_module, key_file, monkeypatch, mode):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    text = "é" * 4000
    assert len(text.encode("utf-8")) == 8000
    observed = []

    async def run():
        completed = asyncio.Event()

        async def serve(reader, writer):
            try:
                request_line = await reader.readline()
                headers = {}
                while (line := await reader.readline()) != b"\r\n":
                    name, value = line.rstrip().split(b":", 1)
                    headers[name.lower()] = value.strip()
                request_body = await reader.readexactly(int(headers[b"content-length"]))
                observed.append((request_line, headers, json.loads(request_body), len(request_body)))
                body = json.dumps(classified()).encode().ljust(8193 if mode == "over" else 8192)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
                chunks = (
                    [body[:4096], body[4096:]]
                    if mode != "slow"
                    else [body[n : n + 512] for n in range(0, len(body), 512)]
                )
                for chunk in chunks:
                    writer.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    await writer.drain()
                    if mode == "slow":
                        await asyncio.sleep(0.025)
                writer.write(b"0\r\n\r\n")
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                writer.close()
                completed.set()

        async with await asyncio.start_server(serve, "127.0.0.1", 0) as server:
            port = server.sockets[0].getsockname()[1]
            config = client_module.ClassifierSettings(
                origin=f"http://127.0.0.1:{port}", key_file=str(key_file), tenant_id=TENANT, allow_loopback_http=True
            )
            client = client_module.PromptClassifierClient(config)
            try:
                budget = 0.4 if mode == "slow" else 1.8
                start = time.monotonic()
                result = await client.assess(
                    client_module.CompletePrompt(text), request_id=REQUEST_ID, deadline=start + budget
                )
                elapsed = time.monotonic() - start
                await asyncio.wait_for(completed.wait(), 2)
            finally:
                await client.aclose()
        return result, elapsed

    result, elapsed = asyncio.run(run())
    ((line, headers, body, size),) = observed
    assert line == b"POST /v1/classify HTTP/1.1\r\n"
    # Avoid exposing even the synthetic bearer in assertion diagnostics.
    assert bool(headers[b"authorization"] == b"Bearer " + key_file.read_bytes().strip())
    assert headers[b"x-tidewall-tenant-id"] == TENANT.encode() and headers[b"accept-encoding"] == b"identity"
    assert size <= 12000
    timeout_ms = body.pop("timeout_ms")
    assert 1 <= timeout_ms <= (250 if mode == "slow" else 1200)
    assert body == {
        "profile": PROFILE,
        "schema_version": 1,
        "request_id": str(REQUEST_ID),
        "event_kind": "prompt",
        "messages": [{"role": "user", "content": text}],
    }
    if mode == "exact":
        assert (result.status, result.reason, result.unsafe_score, result.score_kind, result.input_tokens) == (
            "assessed",
            None,
            0.91,
            SCORE_KIND,
            1024,
        )
        assert json.loads(json.dumps(asdict(result.model_identity))) == MODEL
        with pytest.raises(FrozenInstanceError):
            result.model_identity.base = "replacement"
        assert isinstance(result.model_identity.class_token_ids, tuple)
    elif mode == "over":
        check_no_score(result, "failed", "classifier_invalid")
    else:
        check_no_score(result, "unavailable", "deadline_exceeded")
        assert elapsed < 0.4


@pytest.mark.parametrize(
    ("origin", "allow"),
    [
        ("http://127.0.0.1", False),
        ("http://localhost", True),
        ("http://127.0.0.1.invalid", True),
        ("https://host/path", False),
        ("https://user:URL_SENTINEL@host", False),
        ("https://host?param=URL_SENTINEL", False),
        ("https://host:65536", False),
        ("https://@host", False),
        ("https://host/#fragment", False),
        ("https://host\\@another.invalid", False),
    ],
)
def test_malformed_origin_never_echoed(client_module, key_file, origin, allow):
    with pytest.raises(ValueError) as err:
        client_module.PromptClassifierClient(
            client_module.ClassifierSettings(
                origin=origin, tenant_id=TENANT, key_file=str(key_file), allow_loopback_http=allow
            )
        )
    assert "URL_SENTINEL" not in str(err.value)


@pytest.mark.parametrize(
    "settings",
    [
        {"ORIGIN": "https://URL_SENTINEL.example"},
        {"ORIGIN": "https://a:URL_SENTINEL@host", "TENANT_ID": TENANT, "KEY_FILE": "KEY_PATH_SENTINEL"},
        {"ALLOW_LOOPBACK_HTTP": "URL_SENTINEL"},
        {"TIMEOUT_MS": "URL_SENTINEL"},
        {"TIMEOUT_MS": "1501"},
        {"CA_FILE": "KEY_PATH_SENTINEL"},
    ],
)
def test_bad_operator_config_fails_startup_without_values(tmp_path, monkeypatch, settings):
    from fastapi import FastAPI

    from app.main import lifespan

    monkeypatch.setenv("BOOTSTRAP_KEY", "BOOTSTRAP_SENTINEL")
    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path/'never.db'}")
    for name, value in settings.items():
        monkeypatch.setenv("NATIVE_CLASSIFIER_" + name, value)
    with pytest.raises(ValueError) as err:
        asyncio.run(lifespan(FastAPI()).__aenter__())
    assert "classifier" in str(err.value).lower()
    assert all(word not in str(err.value) for word in ["URL_SENTINEL", "KEY_PATH_SENTINEL", "BOOTSTRAP_SENTINEL"])
    assert not (tmp_path / "never.db").exists()


def test_bounded_operator_key(client_module, key_file):
    key_file.write_bytes(b"x" * 4097)
    with pytest.raises(ValueError):
        client_module.PromptClassifierClient(
            client_module.ClassifierSettings(origin="https://host", tenant_id=TENANT, key_file=str(key_file))
        )


@pytest.mark.parametrize("later_failure", [False, True])
def test_lifespan_owns_and_closes_client(tmp_path, monkeypatch, key_file, later_failure):
    from fastapi import FastAPI

    from app import main

    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path/'life.db'}")
    monkeypatch.setenv("BOOTSTRAP_KEY", uuid4().hex)
    monkeypatch.setenv("NATIVE_CLASSIFIER_ORIGIN", "https://inference.invalid")
    monkeypatch.setenv("NATIVE_CLASSIFIER_TENANT_ID", TENANT)
    monkeypatch.setenv("NATIVE_CLASSIFIER_KEY_FILE", str(key_file))
    settings = Settings.from_env()
    assert "NATIVE_CLASSIFIER_KEY_FILE" not in settings.model_dump()
    assert "inference.invalid" not in repr(settings)
    app = FastAPI()
    if later_failure:

        def fail_ready(message, *args, **kwargs):
            if message == "Tidewall ready":
                raise RuntimeError("later startup failure")

        monkeypatch.setattr(main.logging, "info", fail_ready)

    async def run():
        async with main.lifespan(app):
            assert not app.state.prompt_classifier_client._http.is_closed

    if later_failure:
        with pytest.raises(RuntimeError, match="later startup failure"):
            asyncio.run(run())
    else:
        asyncio.run(run())
    assert app.state.prompt_classifier_client._http.is_closed


def test_duplicate_content_type_is_ambiguous(client_module, key_file):
    def receive(request):
        return httpx.Response(
            200,
            headers=[("content-type", "application/json; charset=utf-8"), ("content-type", "text/plain")],
            stream=httpx.ByteStream(json.dumps(classified()).encode()),
        )

    result = simulated(client_module, key_file, receive)
    check_no_score(result, "failed", "classifier_invalid")


@pytest.mark.parametrize("code,status", [("tenant_mismatch", 403), ("unauthenticated", 401)])
def test_pre_authentication_refusal_cannot_have_parsed_body_identity(client_module, key_file, code, status):
    result = simulated(client_module, key_file, lambda _: reply(status, error(code, False)))
    check_no_score(result, "failed", "classifier_invalid")


@pytest.mark.parametrize("excess", [0, 1])
def test_exact_escaped_service_envelope(client_module, key_file, excess):
    # A 3-digit provider budget fixes the envelope width; preserve edge whitespace and a combining mark.
    prefix = " \te\u0301\n"
    sample = {
        "schema_version": 1,
        "profile": PROFILE,
        "request_id": str(REQUEST_ID),
        "event_kind": "prompt",
        "messages": [{"role": "user", "content": prefix}],
        "timeout_ms": 300,
    }
    overhead = len(json.dumps(sample, separators=(",", ":"), ensure_ascii=False).encode())
    quotes, remainder = divmod(12000 - overhead, 2)
    text = prefix + '"' * quotes + "a" * (remainder + excess)

    def receive(request):
        assert not excess, "oversized escape-heavy envelope was sent"
        assert len(request.content) == 12000
        assert bool(json.loads(request.content)["messages"][0]["content"] == text)
        return reply(200, classified())

    result = simulated(client_module, key_file, receive, text=text, budget=0.6)
    if excess:
        check_no_score(result, "unsupported", "input_too_large")
    else:
        assert result.status == "assessed"


def test_disabled_client_preserves_boot(tmp_path, monkeypatch):
    from fastapi import FastAPI

    from app.main import lifespan

    monkeypatch.setenv("DB_URL", f"sqlite:///{tmp_path/'disabled.db'}")
    monkeypatch.setenv("BOOTSTRAP_KEY", uuid4().hex)
    app = FastAPI()

    async def run():
        async with lifespan(app):
            assert app.state.prompt_classifier_client is None

    asyncio.run(run())


def test_transport_failure_produces_no_score(client_module, key_file):
    def disconnected(request):
        raise httpx.ConnectError("service unavailable")

    result = simulated(client_module, key_file, disconnected)
    check_no_score(result, "unavailable", "classifier_unavailable")


def test_prompt_and_service_configuration_repr_hide_operator_and_input_values(client_module, key_file):
    text = "transient-native-prompt-sentinel"
    assert text not in repr(client_module.CompletePrompt(text))
    settings = client_module.ClassifierSettings(
        origin="https://inference.invalid", key_file=str(key_file), tenant_id=TENANT
    )
    rendered = repr(settings)
    assert "inference.invalid" not in rendered and str(key_file) not in rendered and TENANT not in rendered


def test_empty_ca_file_refused_during_settings_validation(client_module, key_file, monkeypatch):
    monkeypatch.setenv("NATIVE_CLASSIFIER_ORIGIN", "https://inference.invalid")
    monkeypatch.setenv("NATIVE_CLASSIFIER_KEY_FILE", str(key_file))
    monkeypatch.setenv("NATIVE_CLASSIFIER_TENANT_ID", TENANT)
    monkeypatch.setenv("NATIVE_CLASSIFIER_CA_FILE", "")
    with pytest.raises(ValueError, match="CA file"):
        client_module.ClassifierSettings.from_settings(Settings.from_env())


def test_omitted_ca_file_uses_verified_system_trust(client_module, key_file, monkeypatch):
    import ssl
    from unittest.mock import patch

    monkeypatch.setenv("NATIVE_CLASSIFIER_ORIGIN", "https://inference.invalid")
    monkeypatch.setenv("NATIVE_CLASSIFIER_KEY_FILE", str(key_file))
    monkeypatch.setenv("NATIVE_CLASSIFIER_TENANT_ID", TENANT)
    monkeypatch.delenv("NATIVE_CLASSIFIER_CA_FILE", raising=False)
    settings = client_module.ClassifierSettings.from_settings(Settings.from_env())
    with patch.object(httpx, "AsyncClient", wraps=httpx.AsyncClient) as constructor:
        client = client_module.PromptClassifierClient(settings)
        try:
            context = constructor.call_args.kwargs["verify"]
            assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
            assert context.get_ca_certs(binary_form=True) == ssl.create_default_context().get_ca_certs(binary_form=True)
        finally:
            asyncio.run(client.aclose())


def test_unrelated_settings_error_keeps_cause_and_hides_classifier_configuration(monkeypatch):
    from fastapi import FastAPI

    from app.main import lifespan

    monkeypatch.setenv("PREF64", "x")
    monkeypatch.setenv("NATIVE_CLASSIFIER_ORIGIN", "https://inference.invalid")
    monkeypatch.setenv("NATIVE_CLASSIFIER_TENANT_ID", TENANT)
    monkeypatch.setenv("NATIVE_CLASSIFIER_KEY_FILE", "abcdef!")
    with pytest.raises(ValueError) as err:
        asyncio.run(lifespan(FastAPI()).__aenter__())
    message = str(err.value)
    assert "PREF64" in message
    assert "abcdef!" not in message
    assert "input_value=" not in message


def test_one_millisecond_provider_budget_keeps_local_deadline(client_module, key_file, monkeypatch):
    from types import SimpleNamespace

    times = iter((10.0, 10.0002, 10.0004, 10.0011))
    monkeypatch.setattr(client_module, "time", SimpleNamespace(monotonic=lambda: next(times)))
    budgets = []

    def receive(request):
        budgets.append(json.loads(request.content)["timeout_ms"])
        return reply(200, classified())

    async def run():
        config = client_module.ClassifierSettings(
            origin="https://inference.invalid", key_file=str(key_file), tenant_id=TENANT, timeout_ms=1
        )
        client = client_module.PromptClassifierClient(config, transport=httpx.MockTransport(receive))
        try:
            return await client.assess(client_module.CompletePrompt("Hello"), request_id=REQUEST_ID, deadline=10.5)
        finally:
            await client.aclose()

    result = asyncio.run(run())
    assert budgets == [1]
    assert result.reason == "deadline_exceeded"
