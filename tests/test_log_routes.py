"""Integration tests for the logs routes (GET /v1/logs, /v1/logs/stats, /v1/logs/flows)."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.auth.middleware import AuthMiddleware
from app.db.models import APIKey, Base, Interaction
from app.interaction_log import InteractionLog


def _make_app_and_client():
    """Create an in-memory SQLite app with logs router and auth middleware."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = SessionLocal
    app.state.auth_enabled = True
    app.state.interaction_log = InteractionLog(SessionLocal)

    from app.routes import logs

    app.include_router(logs.router)

    # Create admin API key
    raw_admin_key = generate_key(prefix="ak")
    # Create viewer API key
    raw_viewer_key = generate_key(prefix="ak")
    # Create api-role key (below viewer)
    raw_api_key = generate_key(prefix="ak")

    session = SessionLocal()
    session.add(
        APIKey(
            name="test-admin",
            key_hash=hash_key(raw_admin_key),
            key_prefix=key_prefix(raw_admin_key),
            role="admin",
        )
    )
    session.add(
        APIKey(
            name="test-viewer",
            key_hash=hash_key(raw_viewer_key),
            key_prefix=key_prefix(raw_viewer_key),
            role="viewer",
        )
    )
    session.add(
        APIKey(
            name="test-api",
            key_hash=hash_key(raw_api_key),
            key_prefix=key_prefix(raw_api_key),
            role="api",
        )
    )
    session.commit()
    session.close()

    client = TestClient(app)
    return client, raw_admin_key, raw_viewer_key, raw_api_key, SessionLocal


def _seed_interactions(session_factory):
    """Insert sample Interaction rows for testing."""
    session = session_factory()
    rows = [
        Interaction(
            request_id="req-1",
            timestamp="2026-03-01T10:00:00Z",
            event_type="input",
            policy_name="default",
            blocked=True,
            transformed=False,
            status="blocked",
            latency_ms=12.5,
            summary="Blocked prompt injection",
            detectors_json={"prompt_injection": {"detected": True, "score": 0.95}},
            app_id="chat-app",
            user_id="alice",
            model="gpt-4",
            device_id="device-1",
        ),
        Interaction(
            request_id="req-2",
            timestamp="2026-03-01T10:01:00Z",
            event_type="output",
            policy_name="default",
            blocked=False,
            transformed=True,
            status="transformed",
            latency_ms=8.3,
            summary="PII redacted",
            detectors_json={"pii": {"detected": True, "score": 0.8}},
            app_id="chat-app",
            user_id="bob",
            model="gpt-4",
            device_id="device-2",
        ),
        Interaction(
            request_id="req-3",
            timestamp="2026-03-01T10:02:00Z",
            event_type="input",
            policy_name="default",
            blocked=False,
            transformed=False,
            status="allowed",
            latency_ms=5.0,
            summary="Clean request",
            detectors_json={"prompt_injection": {"detected": False, "score": 0.1}},
            app_id="search-app",
            user_id="alice",
            model="claude-3",
            device_id="device-1",
        ),
    ]
    session.add_all(rows)
    session.commit()
    session.close()


@pytest.fixture
def setup():
    client, admin_key, viewer_key, api_key, session_factory = _make_app_and_client()
    _seed_interactions(session_factory)
    return client, admin_key, viewer_key, api_key, session_factory


@pytest.fixture
def empty_setup():
    """Setup with no interaction rows seeded."""
    client, admin_key, viewer_key, api_key, session_factory = _make_app_and_client()
    return client, admin_key, viewer_key, api_key, session_factory


# ------------------------------------------------------------------
# GET /v1/logs
# ------------------------------------------------------------------


def test_get_logs_returns_recent_interactions(setup):
    client, _, viewer_key, _, _ = setup
    resp = client.get(
        "/v1/logs",
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 3
    # Most recent first (ordered by timestamp desc)
    assert data[0]["request_id"] == "req-3"
    assert data[1]["request_id"] == "req-2"
    assert data[2]["request_id"] == "req-1"


def test_get_logs_with_limit(setup):
    client, _, viewer_key, _, _ = setup
    resp = client.get(
        "/v1/logs?limit=2",
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2


def test_get_logs_admin_can_access(setup):
    client, admin_key, _, _, _ = setup
    resp = client.get(
        "/v1/logs",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 3


# ------------------------------------------------------------------
# GET /v1/logs/stats
# ------------------------------------------------------------------


def test_get_stats_returns_aggregate_counts(setup):
    client, _, viewer_key, _, _ = setup
    resp = client.get(
        "/v1/logs/stats",
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert data["blocked"] == 1
    assert data["transformed"] == 1
    assert data["clean"] == 1
    assert "avg_latency_ms" in data
    assert data["avg_latency_ms"] > 0
    # Detector counts: prompt_injection detected once, pii detected once
    assert data["detector_counts"]["prompt_injection"] == 1
    assert data["detector_counts"]["pii"] == 1


# ------------------------------------------------------------------
# GET /v1/logs/flows
# ------------------------------------------------------------------


def test_get_flows_returns_sankey_data(setup):
    client, _, viewer_key, _, _ = setup
    resp = client.get(
        "/v1/logs/flows",
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "links" in data
    assert isinstance(data["nodes"], list)
    assert isinstance(data["links"], list)

    # Verify node categories exist
    categories = {n["category"] for n in data["nodes"]}
    assert "actor" in categories
    assert "application" in categories
    assert "model" in categories

    # Verify link structure
    for link in data["links"]:
        assert "source" in link
        assert "target" in link
        assert "value" in link
        assert link["value"] >= 1
        assert "blocked" in link
        assert "transformed" in link
        assert "clean" in link


# ------------------------------------------------------------------
# Auth: unauthenticated request -> 401
# ------------------------------------------------------------------


def test_logs_unauthenticated_returns_401(setup):
    client, _, _, _, _ = setup
    resp = client.get("/v1/logs")
    assert resp.status_code == 401


def test_stats_unauthenticated_returns_401(setup):
    client, _, _, _, _ = setup
    resp = client.get("/v1/logs/stats")
    assert resp.status_code == 401


def test_flows_unauthenticated_returns_401(setup):
    client, _, _, _, _ = setup
    resp = client.get("/v1/logs/flows")
    assert resp.status_code == 401


# ------------------------------------------------------------------
# Auth: api-role key cannot access logs (viewer+ required)
# ------------------------------------------------------------------


def test_logs_api_role_returns_403(setup):
    client, _, _, api_key, _ = setup
    resp = client.get(
        "/v1/logs",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 403


def test_stats_api_role_returns_403(setup):
    client, _, _, api_key, _ = setup
    resp = client.get(
        "/v1/logs/stats",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 403


def test_flows_api_role_returns_403(setup):
    client, _, _, api_key, _ = setup
    resp = client.get(
        "/v1/logs/flows",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 403


# ------------------------------------------------------------------
# Empty database returns empty/zero results
# ------------------------------------------------------------------


def test_logs_empty_db_returns_empty_list(empty_setup):
    client, _, viewer_key, _, _ = empty_setup
    resp = client.get(
        "/v1/logs",
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


def test_stats_empty_db_returns_zeros(empty_setup):
    client, _, viewer_key, _, _ = empty_setup
    resp = client.get(
        "/v1/logs/stats",
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["blocked"] == 0
    assert data["transformed"] == 0
    assert data["clean"] == 0


def test_flows_empty_db_returns_empty_nodes_and_links(empty_setup):
    client, _, viewer_key, _, _ = empty_setup
    resp = client.get(
        "/v1/logs/flows",
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["nodes"] == []
    assert data["links"] == []
