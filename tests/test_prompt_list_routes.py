"""Prompt-list routes: a rejected pattern must be a 400.

These exist because the P0-12 fix validated patterns in the service and then
mistranslated the result at the HTTP boundary. Create had no catch, so a
rejected pattern surfaced as a 500. Update caught `ValueError` and returned
404 — and `PolicyValidationError` is a `ValueError`, so an administrator
correcting a pattern was told the entry did not exist.

Both were fixed, and the suite stayed green either way, which is why these are
here.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.auth.middleware import AuthMiddleware
from app.db.models import APIKey, Base


@pytest.fixture
def client_and_key():
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

    from app.routes.settings import router

    app.include_router(router)

    raw = generate_key(prefix="ak")
    session = SessionLocal()
    session.add(APIKey(name="admin", key_hash=hash_key(raw), key_prefix=key_prefix(raw), role="admin"))
    session.commit()
    session.close()

    return TestClient(app), raw


def _create(client, key, pattern, match_type="regex"):
    return client.post(
        "/v1/settings/prompt-lists",
        json={"list_type": "malicious", "pattern": pattern, "match_type": match_type},
        headers={"Authorization": f"Bearer {key}"},
    )


@pytest.mark.parametrize(
    "pattern,why",
    [
        ("(", "malformed"),
        (r"(?=secret)x", "lookahead the linear engine will not run"),
        (r"(\w+)\1", "backreference the linear engine will not run"),
    ],
)
def test_creating_a_rejected_pattern_is_400_not_500(client_and_key, pattern, why):
    client, key = client_and_key

    resp = _create(client, key, pattern)

    assert resp.status_code == 400, f"{why} produced {resp.status_code}"


def test_creating_a_valid_pattern_still_works(client_and_key):
    client, key = client_and_key

    resp = _create(client, key, r"secret-\d+")

    assert resp.status_code == 201


def test_updating_to_a_rejected_pattern_is_400_not_404(client_and_key):
    """The entry exists. Reporting it missing sends the administrator hunting
    for the wrong problem."""
    client, key = client_and_key
    entry_id = _create(client, key, r"fine-\d+").json()["id"]

    resp = client.put(
        f"/v1/settings/prompt-lists/{entry_id}",
        json={"pattern": r"(?=secret)x"},
        headers={"Authorization": f"Bearer {key}"},
    )

    assert resp.status_code == 400


def test_switching_match_type_revalidates_the_stored_pattern(client_and_key):
    """The effective pair, not just the field being changed.

    A pattern stored as a harmless substring becomes a regex the moment
    match_type changes, and it has never been validated as one.
    """
    client, key = client_and_key
    entry_id = _create(client, key, r"(?=secret)x", match_type="substring").json()["id"]

    resp = client.put(
        f"/v1/settings/prompt-lists/{entry_id}",
        json={"match_type": "regex"},
        headers={"Authorization": f"Bearer {key}"},
    )

    assert resp.status_code == 400


def test_a_genuinely_missing_entry_is_still_404(client_and_key):
    """The 400 must not have swallowed the not-found case."""
    client, key = client_and_key

    resp = client.put(
        "/v1/settings/prompt-lists/no-such-entry",
        json={"pattern": "fine"},
        headers={"Authorization": f"Bearer {key}"},
    )

    assert resp.status_code == 404
