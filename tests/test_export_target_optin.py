"""The content-export interlock, through the settings API.

Not a consent: the same admin can create the target, set the flag, and hold the
export grant. An explicit, default-off safety interlock, with scope, because a
global boolean approves every policy and both projections at once.
"""

from __future__ import annotations

import pytest

from app.routes.settings import _target_to_dict, validate_content_export_views


class _Target:
    id = "t1"
    name = "n"
    type = "webhook"
    config: dict = {}
    format = "ocsf"
    events: list = []
    enabled = True
    created_at = "2026-08-19"
    allow_content_export = False
    content_export_policy_id = None
    content_export_views: list = []


def test_the_interlock_is_visible_in_the_api():
    out = _target_to_dict(_Target())
    assert out["allow_content_export"] is False
    assert out["content_export_policy_id"] is None
    assert out["content_export_views"] == []


def test_an_absent_view_list_is_an_empty_one():
    assert validate_content_export_views(None) == []
    assert validate_content_export_views([]) == []


def test_the_view_vocabulary_is_closed():
    assert validate_content_export_views(["matches"]) == ["matches"]
    assert validate_content_export_views(["matches", "full"]) == ["matches", "full"]


@pytest.mark.parametrize(
    "raw",
    [
        ["everything"],  # unknown
        ["matches", "matches"],  # duplicate: the caller believes something untrue
        "matches",  # not a list
        [1],
        [None],
        ["Matches"],  # not case-folded for you
    ],
)
def test_a_defective_view_list_is_refused(raw):
    with pytest.raises(ValueError):
        validate_content_export_views(raw)


def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.auth.key_utils import generate_key, hash_key, key_prefix
    from app.auth.middleware import AuthMiddleware
    from app.db.models import APIKey, Base

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.state.session_factory = Session
    from app.routes import settings as settings_routes

    app.include_router(settings_routes.router)  # the router carries its own prefix

    raw = generate_key(prefix="ak")
    session = Session()
    session.add(APIKey(name="admin", key_hash=hash_key(raw), key_prefix=key_prefix(raw), role="admin"))
    session.commit()
    session.close()
    return TestClient(app), {"Authorization": f"Bearer {raw}"}, Session


def test_a_defective_view_list_is_a_400_not_a_500():
    """A caller error must not read as a server fault, and the message must not
    be an exception traceback."""
    client, headers, _ = _client()
    resp = client.post(
        "/v1/settings/export-targets",
        json={
            "name": "t",
            "type": "webhook",
            "config": {},
            "format": "ocsf",
            "events": [],
            "content_export_views": ["everything"],
        },
        headers=headers,
    )
    assert resp.status_code == 400
    assert "everything" in resp.json()["detail"]


def test_a_target_is_created_opted_out_by_default():
    client, headers, _ = _client()
    body = client.post(
        "/v1/settings/export-targets",
        json={"name": "t", "type": "webhook", "config": {}, "format": "ocsf", "events": []},
        headers=headers,
    ).json()
    assert body["allow_content_export"] is False
    assert body["content_export_views"] == []
