"""Integration tests for policy CRUD routes."""

from __future__ import annotations

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.auth.middleware import AuthMiddleware
from app.db.models import APIKey, Base, Policy, RuleSet


def _make_app_and_client():
    """Create an in-memory SQLite app with policy router and auth middleware."""
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

    from app.routes.policies import router

    app.include_router(router)

    # Seed a default policy with detectors
    session = SessionLocal()
    default_policy = Policy(
        name="default_policy",
        type="application",
        description="Default policy for tests",
        report_only=False,
        is_default=True,
    )
    session.add(default_policy)
    session.flush()
    for et in ("input", "output"):
        rs = RuleSet(
            policy_id=default_policy.id,
            event_type=et,
            detectors={"prompt_injection": {"enabled": True, "threshold": 0.8}},
        )
        session.add(rs)
    session.commit()
    default_policy_id = default_policy.id
    session.close()

    # Create admin API key
    raw_admin_key = generate_key(prefix="ak")
    session = SessionLocal()
    session.add(
        APIKey(
            name="test-admin",
            key_hash=hash_key(raw_admin_key),
            key_prefix=key_prefix(raw_admin_key),
            role="admin",
        )
    )
    session.commit()

    # Create viewer API key
    raw_viewer_key = generate_key(prefix="ak")
    session.add(
        APIKey(
            name="test-viewer",
            key_hash=hash_key(raw_viewer_key),
            key_prefix=key_prefix(raw_viewer_key),
            role="viewer",
        )
    )
    session.commit()
    session.close()

    client = TestClient(app)
    return client, raw_admin_key, raw_viewer_key, default_policy_id


@pytest.fixture
def setup():
    client, admin_key, viewer_key, default_policy_id = _make_app_and_client()
    return client, admin_key, viewer_key, default_policy_id


# ------------------------------------------------------------------
# 1. GET /v1/policies — list returns seeded policy
# ------------------------------------------------------------------


def test_list_policies(setup):
    client, admin_key, _, default_policy_id = setup
    resp = client.get(
        "/v1/policies",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    policies = resp.json()
    assert len(policies) >= 1
    names = [p["name"] for p in policies]
    assert "default_policy" in names
    # Check that the default policy has rule_sets
    default = next(p for p in policies if p["id"] == default_policy_id)
    assert len(default["rule_sets"]) == 2


# ------------------------------------------------------------------
# 2. POST /v1/policies — create a new policy
# ------------------------------------------------------------------


def test_create_policy(setup):
    client, admin_key, _, _ = setup
    resp = client.post(
        "/v1/policies",
        json={
            "name": "new-policy",
            "type": "application",
            "description": "A test policy",
            "report_only": True,
            "detectors": {"topic": {"enabled": True}},
        },
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "new-policy"
    assert data["description"] == "A test policy"
    assert data["report_only"] is True
    assert data["is_default"] is False
    assert len(data["rule_sets"]) == 2
    event_types = {rs["event_type"] for rs in data["rule_sets"]}
    assert event_types == {"input", "output"}


# ------------------------------------------------------------------
# 3. GET /v1/policies/{id} — get policy detail with rule sets
# ------------------------------------------------------------------


def test_get_policy_detail(setup):
    client, admin_key, _, default_policy_id = setup
    resp = client.get(
        f"/v1/policies/{default_policy_id}",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == default_policy_id
    assert data["name"] == "default_policy"
    assert data["is_default"] is True
    assert len(data["rule_sets"]) == 2


def test_get_policy_not_found(setup):
    client, admin_key, _, _ = setup
    resp = client.get(
        "/v1/policies/nonexistent-id",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 404


# ------------------------------------------------------------------
# 4. PATCH /v1/policies/{id} — update policy name
# ------------------------------------------------------------------


def test_update_policy_name(setup):
    client, admin_key, _, default_policy_id = setup
    resp = client.patch(
        f"/v1/policies/{default_policy_id}",
        json={"name": "renamed-policy"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "renamed-policy"

    # Verify the change persists
    get_resp = client.get(
        f"/v1/policies/{default_policy_id}",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert get_resp.json()["name"] == "renamed-policy"


def test_update_policy_not_found(setup):
    client, admin_key, _, _ = setup
    resp = client.patch(
        "/v1/policies/nonexistent-id",
        json={"name": "nope"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 404


# ------------------------------------------------------------------
# 5. DELETE /v1/policies/{id} — delete non-default policy
# ------------------------------------------------------------------


def test_delete_non_default_policy(setup):
    client, admin_key, _, _ = setup
    # First create a non-default policy to delete
    create_resp = client.post(
        "/v1/policies",
        json={"name": "to-delete"},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    policy_id = create_resp.json()["id"]

    del_resp = client.delete(
        f"/v1/policies/{policy_id}",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert del_resp.status_code == 204

    # Verify it's gone
    get_resp = client.get(
        f"/v1/policies/{policy_id}",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert get_resp.status_code == 404


def test_delete_default_policy_fails(setup):
    client, admin_key, _, default_policy_id = setup
    resp = client.delete(
        f"/v1/policies/{default_policy_id}",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 400
    assert "default" in resp.json()["detail"].lower()


# ------------------------------------------------------------------
# 6. POST /v1/policies/import — import from YAML-like dict
# ------------------------------------------------------------------


def test_import_policy(setup):
    client, admin_key, _, _ = setup
    resp = client.post(
        "/v1/policies/import",
        json={
            "name": "imported-policy",
            "type": "application",
            "report_only": True,
            "description": "Imported via API",
            "detectors": {"confidential_and_pii_entity": {"enabled": True, "entity_types": ["EMAIL"]}},
        },
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "imported-policy"
    assert data["report_only"] is True
    assert len(data["rule_sets"]) == 2


# ------------------------------------------------------------------
# 7. GET /v1/policies/{id}/export — export returns YAML
# ------------------------------------------------------------------


def test_export_policy_yaml(setup):
    client, admin_key, _, default_policy_id = setup
    resp = client.get(
        f"/v1/policies/{default_policy_id}/export",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    assert "application/x-yaml" in resp.headers["content-type"]
    assert "Content-Disposition" in resp.headers

    parsed = yaml.safe_load(resp.text)
    assert parsed["name"] == "default_policy"
    assert "detectors" in parsed
    assert parsed["detectors"]["prompt_injection"]["enabled"] is True


def test_export_policy_not_found(setup):
    client, admin_key, _, _ = setup
    resp = client.get(
        "/v1/policies/nonexistent-id/export",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 404


# ------------------------------------------------------------------
# 8. Rule set endpoints
# ------------------------------------------------------------------


def test_get_rule_set(setup):
    client, admin_key, _, default_policy_id = setup
    resp = client.get(
        f"/v1/policies/{default_policy_id}/rule-sets/input",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_type"] == "input"
    assert data["policy_id"] == default_policy_id
    assert "prompt_injection" in data["detectors"]


def test_get_rule_set_not_found(setup):
    client, admin_key, _, default_policy_id = setup
    resp = client.get(
        f"/v1/policies/{default_policy_id}/rule-sets/nonexistent",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 404


def test_update_rule_set_detectors(setup):
    client, admin_key, _, default_policy_id = setup
    new_detectors = {
        "malicious_prompt": {"enabled": True, "threshold": 0.9},
        "topic": {"enabled": True, "threshold": 0.7},
    }
    resp = client.patch(
        f"/v1/policies/{default_policy_id}/rule-sets/input",
        json={"detectors": new_detectors},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["detectors"]["topic"]["enabled"] is True
    assert data["detectors"]["malicious_prompt"]["threshold"] == 0.9

    # Verify persistence
    get_resp = client.get(
        f"/v1/policies/{default_policy_id}/rule-sets/input",
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert get_resp.json()["detectors"]["topic"]["threshold"] == 0.7


def test_update_rule_set_not_found(setup):
    client, admin_key, _, default_policy_id = setup
    # A valid body, so this exercises the missing-rule-set path rather than
    # being rejected by validation first.
    resp = client.patch(
        f"/v1/policies/{default_policy_id}/rule-sets/nonexistent",
        json={"detectors": {"topic": {"enabled": True}}},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 404


def test_update_rule_set_rejects_unknown_detector(setup):
    """An unknown detector name is the administrator's error, not a 404.

    It previously succeeded and stored a name nothing would ever load, so the
    policy claimed a control it did not have.
    """
    client, admin_key, _, default_policy_id = setup
    resp = client.patch(
        f"/v1/policies/{default_policy_id}/rule-sets/input",
        json={"detectors": {"no_such_detector": {"enabled": True}}},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 400
    assert "no such detector" in resp.json()["detail"].lower()


def test_update_rule_set_rejects_invalid_regex(setup):
    client, admin_key, _, default_policy_id = setup
    resp = client.patch(
        f"/v1/policies/{default_policy_id}/rule-sets/input",
        json={"detectors": {"custom_entity": {"enabled": True, "patterns": ["(unclosed"]}}},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert resp.status_code == 400
    assert "invalid regex" in resp.json()["detail"].lower()


# ------------------------------------------------------------------
# 9. Auth: viewer can read but not create/update/delete
# ------------------------------------------------------------------


def test_viewer_can_list_policies(setup):
    client, _, viewer_key, _ = setup
    resp = client.get(
        "/v1/policies",
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 200


def test_viewer_can_get_policy(setup):
    client, _, viewer_key, default_policy_id = setup
    resp = client.get(
        f"/v1/policies/{default_policy_id}",
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 200


def test_viewer_can_export_policy(setup):
    client, _, viewer_key, default_policy_id = setup
    resp = client.get(
        f"/v1/policies/{default_policy_id}/export",
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 200


def test_viewer_can_get_rule_set(setup):
    client, _, viewer_key, default_policy_id = setup
    resp = client.get(
        f"/v1/policies/{default_policy_id}/rule-sets/input",
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 200


def test_viewer_cannot_create_policy(setup):
    client, _, viewer_key, _ = setup
    resp = client.post(
        "/v1/policies",
        json={"name": "blocked"},
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 403


def test_viewer_cannot_update_policy(setup):
    client, _, viewer_key, default_policy_id = setup
    resp = client.patch(
        f"/v1/policies/{default_policy_id}",
        json={"name": "blocked"},
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 403


def test_viewer_cannot_delete_policy(setup):
    client, _, viewer_key, default_policy_id = setup
    resp = client.delete(
        f"/v1/policies/{default_policy_id}",
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 403


def test_viewer_cannot_update_rule_set(setup):
    client, _, viewer_key, default_policy_id = setup
    resp = client.patch(
        f"/v1/policies/{default_policy_id}/rule-sets/input",
        json={"detectors": {}},
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 403


def test_viewer_cannot_import_policy(setup):
    client, _, viewer_key, _ = setup
    resp = client.post(
        "/v1/policies/import",
        json={"name": "blocked"},
        headers={"Authorization": f"Bearer {viewer_key}"},
    )
    assert resp.status_code == 403


# ------------------------------------------------------------------
# 10. Auth: unauthenticated requests → 401
# ------------------------------------------------------------------


def test_unauthenticated_list_policies(setup):
    client, _, _, _ = setup
    resp = client.get("/v1/policies")
    assert resp.status_code == 401


def test_unauthenticated_get_policy(setup):
    client, _, _, default_policy_id = setup
    resp = client.get(f"/v1/policies/{default_policy_id}")
    assert resp.status_code == 401


def test_unauthenticated_create_policy(setup):
    client, _, _, _ = setup
    resp = client.post("/v1/policies", json={"name": "nope"})
    assert resp.status_code == 401


def test_unauthenticated_delete_policy(setup):
    client, _, _, default_policy_id = setup
    resp = client.delete(f"/v1/policies/{default_policy_id}")
    assert resp.status_code == 401


def test_unauthenticated_export_policy(setup):
    client, _, _, default_policy_id = setup
    resp = client.get(f"/v1/policies/{default_policy_id}/export")
    assert resp.status_code == 401


def test_unauthenticated_import_policy(setup):
    client, _, _, _ = setup
    resp = client.post("/v1/policies/import", json={"name": "nope"})
    assert resp.status_code == 401
