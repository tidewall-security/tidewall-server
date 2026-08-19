"""The grants vocabulary, its validator, and the one implication."""

from __future__ import annotations

import pytest

from app.auth.grants import (
    CONTENT_EXPORT,
    CONTENT_READ,
    GRANTS,
    MATCHES_READ,
    GrantError,
    allows_view,
    grant_for,
    validate_grants,
)


def test_null_and_empty_normalise_to_the_same_thing():
    """Every key that existed before this step has NULL, including the
    bootstrap admin. That is the compatible case, not a defect."""
    assert validate_grants("viewer", "p", None) == frozenset()
    assert validate_grants("viewer", "p", []) == frozenset()
    # And with no grants, the role and binding rules do not apply at all.
    assert validate_grants("api", None, None) == frozenset()


@pytest.mark.parametrize(
    "raw",
    [
        "interaction:matches:read",  # a bare string, not a list
        {"interaction:matches:read"},  # a set
        [MATCHES_READ, MATCHES_READ],  # duplicate
        [None],
        [123],
        [b"interaction:matches:read"],
        ["interaction:matches:READ"],  # not lowercased for you
        ["interaction:matches:read "],  # not stripped for you
        ["interaction:matches"],  # not prefix-matched
        [MATCHES_READ, CONTENT_READ, CONTENT_EXPORT, MATCHES_READ],  # oversized
    ],
)
def test_a_defective_grant_set_raises(raw):
    with pytest.raises(GrantError):
        validate_grants("viewer", "p", raw)


@pytest.mark.parametrize("role", ["api", "rt", "unknown", None, ""])
def test_only_viewer_and_admin_may_hold_a_grant(role):
    """An admin administers policies; that is a different question from whether
    they may read the prompts. But api and rt are not in that conversation."""
    with pytest.raises(GrantError):
        validate_grants(role, "p", [MATCHES_READ])


@pytest.mark.parametrize("policy_id", [None, "", 0, False])
def test_a_null_binding_never_means_all_policies(policy_id):
    with pytest.raises(GrantError):
        validate_grants("admin", policy_id, [CONTENT_READ])


def test_the_implication_runs_one_way_only():
    """Full implies matches. Matches does not imply full, and export implies
    neither."""
    assert allows_view(frozenset({CONTENT_READ}), "matches")
    assert allows_view(frozenset({CONTENT_READ}), "full")
    assert allows_view(frozenset({MATCHES_READ}), "matches")
    assert not allows_view(frozenset({MATCHES_READ}), "full")
    assert not allows_view(frozenset({CONTENT_EXPORT}), "matches")
    assert not allows_view(frozenset({CONTENT_EXPORT}), "full")
    assert not allows_view(frozenset(), "matches")


def test_an_unknown_view_is_never_allowed():
    assert not allows_view(GRANTS, "everything")
    assert not allows_view(GRANTS, "")


def test_grant_for_is_least_privilege():
    """The authorization rule exercised, not the strongest grant held. Making
    the audit depend on unrelated grants attached to the same key would
    overstate what the request used."""
    assert grant_for("matches") == MATCHES_READ
    assert grant_for("full") == CONTENT_READ
    with pytest.raises(ValueError):
        grant_for("everything")


def test_the_implication_is_never_persisted():
    """It is applied at read time and nowhere else, so a later export check
    cannot inherit it by accident."""
    validated = validate_grants("viewer", "p", [CONTENT_READ])
    assert validated == frozenset({CONTENT_READ})
    assert MATCHES_READ not in validated


# ---------------------------------------------------------------------------
# require_role's three failures
# ---------------------------------------------------------------------------


def test_an_unknown_minimum_role_raises_at_construction():
    """A programmer error, so it fails at import where it is a test failure,
    not at runtime as a response whose shape a caller can influence."""
    from app.auth.dependencies import require_role

    with pytest.raises(ValueError, match="unknown minimum_role"):
        require_role("superuser")


@pytest.mark.parametrize("minimum", ["admin", "viewer", "api", "rt"])
def test_every_real_minimum_role_still_constructs(minimum):
    from app.auth.dependencies import require_role

    assert require_role(minimum) is not None


def test_an_unknown_role_is_no_longer_the_lowest_valid_one():
    """_ROLE_HIERARCHY.get(role, 0) mapped an unknown role to level zero -- the
    rt level -- so a typo or a tampered row became the lowest *valid* role
    rather than no role at all."""
    from fastapi import HTTPException

    from app.auth.dependencies import require_role

    class _State:
        role = "superuser"

    class _Request:
        state = _State()

    import asyncio

    check = require_role("rt")  # the level an unknown role used to be given
    with pytest.raises(HTTPException) as caught:
        asyncio.run(check(_Request()))
    assert caught.value.status_code == 403


# ---------------------------------------------------------------------------
# The SQLite invariant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "db_url",
    [
        "sqlite:///data/tidewall.db",
        "sqlite:///:memory:",
        "sqlite://",
        "sqlite+pysqlite:///x.db",
    ],
)
def test_every_sqlite_form_is_accepted(db_url):
    from app.db.engine import require_sqlite

    require_sqlite(db_url)


@pytest.mark.parametrize(
    "db_url",
    [
        "postgresql://u:p@h/db",
        "mysql+pymysql://u:p@h/db",
        # Starts with "sqlite" and is not SQLite. A prefix check let this
        # through to fail later in dialect loading instead of here.
        "sqliteevil://h/db",
        "not a url at all",
    ],
)
def test_a_non_sqlite_url_is_refused_clearly(db_url):
    from app.db.engine import require_sqlite

    with pytest.raises(RuntimeError) as caught:
        require_sqlite(db_url)
    assert "SQLite" in str(caught.value) or "not a valid database URL" in str(caught.value)


def test_the_bootstrap_admin_has_no_content_access():
    """Administering policies is not the same question as reading the prompts."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.db.models import APIKey, Base
    from app.services.key_service import KeyService

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        assert KeyService(session).install_bootstrap_admin_key("ak_bootstrap_secret_value") is True
        key = session.query(APIKey).one()
        assert key.role == "admin"
        assert not (key.grants or []), "the bootstrap admin was given a content grant"
        assert validate_grants(key.role, key.policy_id, key.grants) == frozenset()
    finally:
        session.close()
        engine.dispose()
