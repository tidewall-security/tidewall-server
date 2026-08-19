"""The audited one-record content API: authorization, scope, and audit.

Step 5's rule was that optional capture must never change the security
decision. This inverts it: the access audit is a precondition of disclosure. A
test that lets content out without a durable audit row is testing the wrong
thing.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.grants import CONTENT_EXPORT, CONTENT_READ, MATCHES_READ
from app.auth.key_utils import generate_key, hash_key, key_prefix
from app.auth.middleware import AuthMiddleware
from app.db.models import APIKey, Base, ContentAccessAudit, Interaction, InteractionContent, Policy
from app.security_headers import SecurityHeadersMiddleware

CANARY = "swordfish-42"


@pytest.fixture
def env():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.session_factory = Session

    from app.routes import content

    app.include_router(content.router)

    session = Session()
    for name in ("policy-a", "policy-b"):
        session.add(Policy(id=name, name=name, type="application"))
    session.commit()
    session.close()

    return TestClient(app), Session


def _key(Session, *, role="viewer", policy_id="policy-a", grants=None):
    raw = generate_key(prefix="ak")
    session = Session()
    session.add(
        APIKey(
            name=f"k-{raw[-6:]}",
            key_hash=hash_key(raw),
            key_prefix=key_prefix(raw),
            role=role,
            policy_id=policy_id,
            grants=grants,
        )
    )
    session.commit()
    session.close()
    return {"Authorization": f"Bearer {raw}"}


_next_request_id = 0


def _interaction(Session, *, policy_id="policy-a", content=True, expires_at=None, matches=None, tools=None):
    global _next_request_id
    _next_request_id += 1
    session = Session()
    row = Interaction(
        request_id=f"tw_{_next_request_id:016x}",
        timestamp="2026-08-19T00:00:00Z",
        event_type="input",
        policy_id=policy_id,
        policy_name=policy_id,
        blocked=False,
        transformed=False,
        latency_ms=1.0,
        content_available=content,
    )
    session.add(row)
    session.flush()
    interaction_id = row.id
    if content:
        payload = (
            {"messages": [{"role": "user", "content": CANARY}], "tools": tools}
            if tools is not None
            else [{"role": "user", "content": CANARY}]
        )
        session.add(
            InteractionContent(
                interaction_id=interaction_id,
                policy_id=policy_id,
                input_json=payload,
                output_json=[{"role": "assistant", "content": "reply"}],
                matches_json=matches
                if matches is not None
                else {
                    "schema_version": 1,
                    "matches": [
                        {
                            "detector": "custom_entity",
                            "match_type": "CUSTOM",
                            "rule_id": None,
                            "source": {"kind": "message", "index": 0, "field": "content", "role": "user"},
                            "value": CANARY,
                            "occurrences": 1,
                        }
                    ],
                },
                byte_size=10,
                captured_at=datetime.now(UTC),
                expires_at=expires_at,
            )
        )
    session.commit()
    session.close()
    return interaction_id


def _audits(Session):
    session = Session()
    try:
        return session.query(ContentAccessAudit).order_by(ContentAccessAudit.id).all()
    finally:
        session.close()


# ---------------------------------------------------------------------------
# The authorization matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "role,policy_id,grants,view,expected",
    [
        # No grant is no access, whatever the role. An admin administers
        # policies; that is a different question from reading the prompts.
        ("viewer", "policy-a", None, "matches", 403),
        ("viewer", "policy-a", None, "full", 403),
        ("admin", "policy-a", None, "matches", 403),
        ("admin", "policy-a", None, "full", 403),
        # The grant does exactly what it says.
        ("viewer", "policy-a", [MATCHES_READ], "matches", 200),
        ("viewer", "policy-a", [MATCHES_READ], "full", 403),
        ("viewer", "policy-a", [CONTENT_READ], "matches", 200),
        ("viewer", "policy-a", [CONTENT_READ], "full", 200),
        ("admin", "policy-a", [CONTENT_READ], "full", 200),
        # Export implies neither read.
        ("viewer", "policy-a", [CONTENT_EXPORT], "matches", 403),
        ("viewer", "policy-a", [CONTENT_EXPORT], "full", 403),
        # A null binding never means "all policies" for content.
        ("admin", None, None, "matches", 403),
        ("admin", None, None, "full", 403),
        # Roles that cannot hold a grant at all.
        ("api", "policy-a", None, "matches", 403),
    ],
)
def test_the_authorization_matrix(env, role, policy_id, grants, view, expected):
    client, Session = env
    headers = _key(Session, role=role, policy_id=policy_id, grants=grants)
    interaction_id = _interaction(Session)
    resp = client.get(f"/v1/logs/{interaction_id}/content?view={view}", headers=headers)
    assert resp.status_code == expected


def test_an_unbound_admin_with_a_persisted_grant_is_refused_authentication(env):
    """A grant on an unbound key is not a weaker credential; it is an invalid one.

    Validated at authentication rather than only at creation, because a row can
    be written by a test, a script or a hand edit. 401 rather than 403: 403
    would confirm the bearer secret is real and merely misconfigured.
    """
    client, Session = env
    headers = _key(Session, role="admin", policy_id=None, grants=[CONTENT_READ])
    interaction_id = _interaction(Session)
    resp = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers)
    assert resp.status_code == 401
    assert resp.json() == {"detail": "Invalid API key"}


@pytest.mark.parametrize(
    "grants",
    [
        ["interaction:content:admin"],  # unknown
        [MATCHES_READ, MATCHES_READ],  # duplicate
        [123],  # not a string
        "interaction:matches:read",  # not a list
        [MATCHES_READ, CONTENT_READ, CONTENT_EXPORT, MATCHES_READ],  # oversized
    ],
)
def test_a_defective_persisted_grant_makes_the_credential_invalid(env, grants):
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=grants)
    interaction_id = _interaction(Session)
    resp = client.get(f"/v1/logs/{interaction_id}/content?view=matches", headers=headers)
    assert resp.status_code == 401, "a defective grant set authenticated"


def test_null_and_empty_grants_are_the_compatible_case(env):
    """Every key that existed before this step has NULL. That is no content
    access, not a broken credential."""
    client, Session = env
    interaction_id = _interaction(Session)
    for grants in (None, []):
        headers = _key(Session, role="viewer", policy_id="policy-a", grants=grants)
        resp = client.get(f"/v1/logs/{interaction_id}/content?view=matches", headers=headers)
        assert resp.status_code == 403, "NULL or [] should authenticate and then be denied"


# ---------------------------------------------------------------------------
# Non-enumerability
# ---------------------------------------------------------------------------


def test_a_foreign_interaction_is_indistinguishable_from_one_that_does_not_exist(env):
    """The accepted plan's matrix says wrong policy is 403 and its own
    non-enumerability requirement needs 404. Both cannot hold: with sequential
    integer ids, 403-for-real-elsewhere against 404-for-absent is an existence
    oracle over the whole tenant space, cheap to walk.

    Uniform 404, and asserted on the bytes rather than the status alone.
    """
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    foreign_id = _interaction(Session, policy_id="policy-b")
    absent_id = foreign_id + 10_000

    foreign = client.get(f"/v1/logs/{foreign_id}/content?view=full", headers=headers)
    absent = client.get(f"/v1/logs/{absent_id}/content?view=full", headers=headers)

    assert foreign.status_code == absent.status_code == 404
    assert foreign.content == absent.content, "the response body distinguishes them"
    ignored = {"date", "server", "content-length"}
    assert {k.lower(): v for k, v in foreign.headers.items() if k.lower() not in ignored} == {
        k.lower(): v for k, v in absent.headers.items() if k.lower() not in ignored
    }, "the headers distinguish them"

    # The audit rows differ only in the id that was asked for, which is not
    # caller-visible.
    rows = _audits(Session)
    assert len(rows) == 2
    for row in rows:
        assert row.outcome == "denied_scope"
        assert row.reason == "no_such_interaction", "a foreign row must not be classified as existing"


def test_the_load_query_is_policy_scoped_in_sql(env):
    """Asserted as SQL, not inferred from behaviour. An unscoped load followed
    by a Python comparison would pass a status test while still putting the
    wrong row in memory."""
    from app.routes.content import _select

    compiled = str(_select(1, "policy-a", datetime.now(UTC)).compile())
    normalised = " ".join(compiled.split())
    assert "interactions.policy_id = " in normalised, "the interaction is not policy-scoped"
    assert normalised.count("policy_id = ") >= 2, "the content join is not policy-scoped"


def test_a_content_row_whose_policy_disagrees_is_excluded_by_the_query(env):
    """The duplicated policy is the point of duplicating it. Detected on read
    and excluded in SQL, not prevented -- SQLite cannot express a cross-table
    equality without a trigger."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)

    session = Session()
    row = session.query(InteractionContent).filter_by(interaction_id=interaction_id).one()
    row.policy_id = "policy-b"
    session.commit()
    session.close()

    resp = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers)
    assert resp.status_code == 404
    assert CANARY not in resp.text
    # The caller sees the same 404 as everything else; the operator gets the reason.
    assert _audits(Session)[-1].reason == "policy_mismatch"


def test_the_audit_classifies_what_the_caller_cannot_see(env):
    """One uniform 404 for four causes. An operator investigating a denial needs
    to know which, and the caller never sees the audit."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])

    no_content = _interaction(Session, content=False)
    expired = _interaction(Session, expires_at=datetime.now(UTC) - timedelta(days=1))

    assert client.get(f"/v1/logs/{no_content}/content?view=full", headers=headers).status_code == 404
    assert client.get(f"/v1/logs/{expired}/content?view=full", headers=headers).status_code == 404

    reasons = [r.reason for r in _audits(Session)]
    assert reasons == ["no_content_row", "expired"]


# ---------------------------------------------------------------------------
# The audit is a precondition
# ---------------------------------------------------------------------------


def test_no_content_without_a_committed_audit(env, monkeypatch):
    """Step 5's inversion. Capture's failure must not propagate because it
    observes a decision already made; this audit records a disclosure that has
    not happened yet, so its failure must prevent it."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)

    import app.routes.content as content_module

    def _explode(*_args, **_kwargs):
        raise RuntimeError("audit table unavailable")

    monkeypatch.setattr(content_module, "_audit", _explode)
    resp = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers)

    assert resp.status_code == 503, "content was disclosed without a durable audit"
    assert CANARY not in resp.text
    assert "RuntimeError" not in resp.text and "audit table" not in resp.text


def test_an_audit_failure_is_503_not_500(env, monkeypatch):
    """The endpoint's outer catch is a last resort only. An audit failure
    handled beneath it must not surface as an internal error."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)

    import app.routes.content as content_module

    monkeypatch.setattr(content_module, "_audit", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    assert client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers).status_code == 503


def test_a_denial_audit_failure_keeps_the_denial(env, monkeypatch):
    """Converting a denial to 503 would restore no audit, deny nothing further,
    and add a second oracle."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=None)
    interaction_id = _interaction(Session)

    import app.routes.content as content_module

    monkeypatch.setattr(content_module, "_audit", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    assert client.get(f"/v1/logs/{interaction_id}/content?view=matches", headers=headers).status_code == 403


def test_the_audit_records_the_rule_exercised_not_the_authority_held(env):
    """A key with both grants asking for matches exercised the matches rule.
    Recording the strongest grant held would make the audit depend on unrelated
    grants attached to the same key."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[MATCHES_READ, CONTENT_READ])
    interaction_id = _interaction(Session)

    assert client.get(f"/v1/logs/{interaction_id}/content?view=matches", headers=headers).status_code == 200
    assert _audits(Session)[-1].grant_used == MATCHES_READ

    assert client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers).status_code == 200
    assert _audits(Session)[-1].grant_used == CONTENT_READ


def test_the_audit_records_who_and_what_never_the_content(env):
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)
    client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers)

    row = _audits(Session)[-1]
    assert row.outcome == "authorized"
    assert row.tier == "full"
    assert row.actor_role == "viewer"
    assert row.policy_id == "policy-a"
    assert row.interaction_id == interaction_id
    assert row.attempt_id and len(row.attempt_id) == 32
    assert CANARY not in json.dumps({c.name: str(getattr(row, c.name)) for c in row.__table__.columns})


# ---------------------------------------------------------------------------
# Projections, corruption, and the fetch-time decoding trap
# ---------------------------------------------------------------------------


def test_the_matches_view_returns_matches_and_not_the_prompt(env):
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[MATCHES_READ])
    interaction_id = _interaction(Session)

    body = client.get(f"/v1/logs/{interaction_id}/content?view=matches", headers=headers).json()
    assert set(body) == {"interaction_id", "view", "captured_at", "expires_at", "matches"}
    assert body["matches"]["schema_version"] == 1
    assert body["matches"]["matches"][0]["value"] == CANARY
    assert "messages" not in body and "output" not in body


def test_the_full_view_returns_the_captured_request(env):
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session, tools=[{"name": "search"}])

    body = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers).json()
    assert set(body) == {
        "interaction_id",
        "view",
        "captured_at",
        "expires_at",
        "messages",
        "tools",
        "output",
        "matches",
    }
    assert body["messages"][0]["content"] == CANARY
    assert body["tools"] == [{"name": "search"}]
    assert "byte_size" not in body and "policy_id" not in body


def test_a_bare_input_list_yields_null_tools(env):
    """build_content writes the wrapper only when tools were supplied at all.
    There is no tools column to read instead, and every field is always present
    with null carrying the meaning."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)  # bare list
    body = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers).json()
    assert body["tools"] is None
    assert "tools" in body, "the field must be present, not omitted"


def test_the_matches_view_does_not_decode_the_prompt(env):
    """Corruption in a column this view does not serve cannot fail it, and a
    caller without the full grant should not have the prompt decoded on their
    behalf."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)

    session = Session()
    session.execute(
        InteractionContent.__table__.update()
        .where(InteractionContent.interaction_id == interaction_id)
        .values(input_json="{not json at all")
    )
    session.commit()
    session.close()

    assert client.get(f"/v1/logs/{interaction_id}/content?view=matches", headers=headers).status_code == 200
    assert client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers).status_code == 500


def test_malformed_stored_json_is_classified_not_a_bare_500(env):
    """SQLAlchemy's JSON result processor decodes during row fetch, which would
    raise before anything could classify the row or write its audit. The payload
    columns are cast to TEXT so the failure lands inside the boundary that can."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)

    session = Session()
    session.execute(
        InteractionContent.__table__.update()
        .where(InteractionContent.interaction_id == interaction_id)
        .values(matches_json="{broken")
    )
    session.commit()
    session.close()

    resp = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers)
    assert resp.status_code == 500
    assert CANARY not in resp.text
    assert _audits(Session)[-1].outcome == "denied_corrupt", "a corrupt read was not audited"


@pytest.mark.parametrize("stored", ["0000", "9999-99-99 99:99:99.000000", "2026-08-19T00:00:00+05:00"])
def test_a_malformed_expiry_is_corrupt_whichever_side_of_now_it_sorts(env, stored):
    """SQL cannot both classify expiry and vouch that the stored value is valid.
    A malformed "0000" sorts before now and would return 404 unparsed; a later
    one sorts after and would return 500. Parsing first, and accepting only the
    canonical stored form, makes the answer the same for both -- including for a
    value that parses but is not canonical."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)

    # Raw SQL: the ORM's DateTime type refuses a string, which is the whole
    # point -- only a hand-edited or foreign row can hold one.
    session = Session()
    session.execute(
        sa.text("UPDATE interaction_contents SET expires_at = :v WHERE interaction_id = :i"),
        {"v": stored, "i": interaction_id},
    )
    session.commit()
    session.close()

    resp = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers)
    assert resp.status_code == 500, f"{stored!r} was not classified as corrupt"
    assert _audits(Session)[-1].outcome == "denied_corrupt"


@pytest.mark.parametrize(
    "matches",
    [
        {"schema_version": 2, "matches": []},
        {"schema_version": True, "matches": []},
        {"schema_version": "1", "matches": []},
        {"schema_version": 1, "matches": [{"detector": "d"}]},
        {"schema_version": 1, "extra": 1, "matches": []},
    ],
)
def test_an_unexpected_match_shape_is_corrupt(env, matches):
    """This system wrote these itself, so an unexpected shape is tampering or
    version skew rather than a permissive caller."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[MATCHES_READ])
    interaction_id = _interaction(Session, matches=matches)
    assert client.get(f"/v1/logs/{interaction_id}/content?view=matches", headers=headers).status_code == 500


def test_an_unknown_source_vocabulary_value_is_still_served(env):
    """Those vocabularies can grow inside schema version 1 and drive no
    authorization, parsing or control flow. schema_version is the version gate;
    rejecting evidence over a vocabulary addition would destroy readable
    forensic data to no purpose."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[MATCHES_READ])
    interaction_id = _interaction(
        Session,
        matches={
            "schema_version": 1,
            "matches": [
                {
                    "detector": "d",
                    "match_type": "T",
                    "rule_id": None,
                    "source": {"kind": "attachment", "index": 0, "field": "filename", "role": None},
                    "value": "v",
                    "occurrences": 1,
                }
            ],
        },
    )
    resp = client.get(f"/v1/logs/{interaction_id}/content?view=matches", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["matches"]["matches"][0]["source"]["kind"] == "attachment"


# ---------------------------------------------------------------------------
# Syntax, ordering, headers, and bypass attempts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    ["", "?view=", "?view=matches&view=full", "?view=MATCHES", "?view=both", "?view=matches&view=matches"],
)
def test_a_bad_view_is_400_not_fastapis_422(env, query):
    """The route declares no typed parameters on purpose: a typed or Literal
    parameter lets FastAPI produce a 422 before any application code runs."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)
    assert client.get(f"/v1/logs/{interaction_id}/content{query}", headers=headers).status_code == 400


@pytest.mark.parametrize("raw_id", ["abc", "-1", "0", "1.5", "1e3", str(2**63), " 1"])
def test_a_bad_interaction_id_is_400_before_any_query(env, raw_id):
    """Range-checked before the query so a Python integer larger than SQLite can
    hold never reaches the driver."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    resp = client.get(f"/v1/logs/{raw_id}/content?view=full", headers=headers)
    assert resp.status_code == 400, f"{raw_id!r} was not rejected"


def test_syntax_is_checked_before_authorization(env):
    """Fixed order, asserted rather than assumed. A caller with no grant and a
    bad view gets the syntax answer, so the two checks cannot be reordered
    silently."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=None)
    interaction_id = _interaction(Session)
    assert client.get(f"/v1/logs/{interaction_id}/content?view=bogus", headers=headers).status_code == 400


def test_no_audit_is_written_for_a_syntax_failure(env):
    """The contract is every authenticated content-access *decision*, not every
    HTTP request touching the path. A malformed request is not a decision."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)
    client.get(f"/v1/logs/{interaction_id}/content?view=bogus", headers=headers)
    assert _audits(Session) == []


def test_unauthenticated_is_401_and_writes_no_audit(env):
    client, Session = env
    interaction_id = _interaction(Session)
    assert client.get(f"/v1/logs/{interaction_id}/content?view=full").status_code == 401
    assert _audits(Session) == []


@pytest.mark.parametrize("status_case", ["ok", "denied", "not_found", "bad_request"])
def test_every_response_is_uncacheable(env, status_case):
    """A 404 saying "that content is not yours" is worth not caching too."""
    client, Session = env
    grants = [CONTENT_READ] if status_case != "denied" else None
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=grants)
    interaction_id = _interaction(Session)
    target = {
        "ok": f"/v1/logs/{interaction_id}/content?view=full",
        "denied": f"/v1/logs/{interaction_id}/content?view=full",
        "not_found": f"/v1/logs/{interaction_id + 9999}/content?view=full",
        "bad_request": f"/v1/logs/{interaction_id}/content?view=bogus",
    }[status_case]

    resp = client.get(target, headers=headers)
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["pragma"] == "no-cache"
    assert resp.headers["x-content-type-options"] == "nosniff"
    # The global framing policy is preserved, not replaced.
    assert resp.headers["content-security-policy"] == "frame-ancestors 'none'"


def test_the_middleware_covers_an_authentication_short_circuit(env):
    """A 401 is returned by AuthMiddleware, so the route cannot header it.
    SecurityHeadersMiddleware is registered after AuthMiddleware and middleware
    runs in reverse registration order, so it is the outer of the two."""
    client, Session = env
    interaction_id = _interaction(Session)
    resp = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers={"Authorization": "Bearer ak_nope"})
    assert resp.status_code == 401
    assert resp.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_no_other_method_reaches_the_endpoint(env, method):
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)
    resp = getattr(client, method)(f"/v1/logs/{interaction_id}/content?view=full", headers=headers)
    assert resp.status_code == 405


def test_there_is_no_bulk_form(env):
    """No list, range, id set, search or prefetch was added."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    _interaction(Session)
    for path in ("/v1/logs/content", "/v1/logs/1-5/content", "/v1/logs/all/content", "/v1/content"):
        resp = client.get(f"{path}?view=full", headers=headers)
        assert resp.status_code in (400, 404, 405), f"{path} returned {resp.status_code}"
        assert CANARY not in resp.text


# ---------------------------------------------------------------------------
# The audit boundary covers acquisition, rollback and close
# ---------------------------------------------------------------------------


def test_an_audit_session_that_cannot_be_acquired_is_still_503(env, monkeypatch):
    """Acquisition sat outside the boundary, so a factory failure reached the
    endpoint's last-resort catch and turned the required 503 into a 500. The
    earlier tests patched _audit only after a session already existed, so they
    passed while this survived."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)

    calls = {"n": 0}

    def _factory():
        # 1 = the authentication lookup, 2 = the scoped read, 3 = the audit.
        calls["n"] += 1
        if calls["n"] > 2:
            raise RuntimeError("no session for you")
        return Session()

    client.app.state.session_factory = _factory
    try:
        resp = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers)
    finally:
        client.app.state.session_factory = Session

    assert resp.status_code == 503, "an audit session failure became an internal error"
    assert CANARY not in resp.text


def test_an_audit_session_failure_on_a_denial_keeps_the_denial(env):
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=None)
    interaction_id = _interaction(Session)

    calls = {"n": 0}

    def _factory():
        calls["n"] += 1
        if calls["n"] > 1:
            raise RuntimeError("no session for you")
        return Session()

    client.app.state.session_factory = _factory
    try:
        resp = client.get(f"/v1/logs/{interaction_id}/content?view=matches", headers=headers)
    finally:
        client.app.state.session_factory = Session

    assert resp.status_code == 403, "an audit session failure replaced the denial"


def test_a_close_failure_after_a_successful_audit_does_not_become_a_500(env, monkeypatch):
    """close() sat in a finally outside the handler, so a close failure after a
    successful commit escaped and turned an authorized read into a 500 the
    caller cannot distinguish from a real fault."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)

    real_close = Session.class_.close
    state = {"closes": 0}

    def _close(self):
        # 1 = authentication, 2 = the scoped read, 3 = the audit session, which
        # is the one whose close used to escape the boundary.
        state["closes"] += 1
        if state["closes"] >= 3:
            raise RuntimeError("close failed")
        return real_close(self)

    monkeypatch.setattr(Session.class_, "close", _close)
    resp = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers)
    assert resp.status_code == 200, "a close failure became an internal error"


def test_audit_failures_are_counted(env, monkeypatch):
    """There is no metrics system here, so this is a process counter whose
    running total goes into each failure record -- log-based alerting is what an
    operator actually has today."""
    import app.routes.content as content_module

    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)

    before = content_module.audit_failure_count()
    monkeypatch.setattr(content_module, "_audit", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers)

    assert content_module.audit_failure_count() == before + 1


# ---------------------------------------------------------------------------
# Canonical rendering, null equivalence, and the unhandled-exception path
# ---------------------------------------------------------------------------


def test_timestamps_render_canonically(env):
    """ "ISO-8601 UTC" does not determine a unique body: Z against +00:00, and
    trimmed against padded fractional seconds, are all defensible."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session, expires_at=datetime.now(UTC) + timedelta(days=1))

    body = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers).json()
    for value in (body["captured_at"], body["expires_at"]):
        assert value.endswith("Z"), value
        assert "+00:00" not in value


def test_no_expiry_renders_as_null_not_a_string(env):
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)  # no expiry configured
    assert client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers).json()["expires_at"] is None


def test_sql_null_and_json_null_produce_the_same_body(env):
    """Both mean "nothing was captured for this field". Inventing a difference
    between them would expose how the row happened to be written."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])

    sql_null = _interaction(Session)
    json_null = _interaction(Session)
    session = Session()
    session.execute(
        sa.text("UPDATE interaction_contents SET output_json = NULL WHERE interaction_id = :i"),
        {"i": sql_null},
    )
    session.execute(
        sa.text("UPDATE interaction_contents SET output_json = 'null' WHERE interaction_id = :i"),
        {"i": json_null},
    )
    session.commit()
    session.close()

    a = client.get(f"/v1/logs/{sql_null}/content?view=full", headers=headers).json()
    b = client.get(f"/v1/logs/{json_null}/content?view=full", headers=headers).json()
    assert a["output"] is None and b["output"] is None
    assert set(a) == set(b), "the two null forms produced different fields"


def test_every_field_is_present_even_when_everything_is_null(env):
    """No absent-versus-null rule to get wrong: null carries the meaning."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)
    session = Session()
    session.execute(
        sa.text(
            "UPDATE interaction_contents SET input_json = NULL, output_json = NULL, "
            "matches_json = NULL WHERE interaction_id = :i"
        ),
        {"i": interaction_id},
    )
    session.commit()
    session.close()

    body = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers).json()
    assert set(body) == {
        "interaction_id",
        "view",
        "captured_at",
        "expires_at",
        "messages",
        "tools",
        "output",
        "matches",
    }
    assert body["messages"] is None and body["matches"] is None


def test_a_genuinely_unhandled_exception_is_a_fixed_500_with_the_headers(env, monkeypatch):
    """Through the production stack, not an explicitly constructed 500 Response,
    which would prove nothing about the path that matters."""
    import app.routes.content as content_module

    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)

    def _explode(*_args, **_kwargs):
        raise RuntimeError("boom in the projection")

    monkeypatch.setattr(content_module, "_select", _explode)
    resp = client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers)

    assert resp.status_code == 500
    assert resp.json() == {"detail": "Internal error"}
    assert "boom" not in resp.text and "RuntimeError" not in resp.text
    assert resp.headers["cache-control"] == "no-store"


def test_a_non_finite_number_in_stored_content_is_corrupt(env):
    """Python's json accepts NaN and Infinity, which are not JSON, so
    build_content can already have written one. Under an application/json
    contract, emitting a non-standard token or coercing it are both worse than
    refusing."""
    client, Session = env
    headers = _key(Session, role="viewer", policy_id="policy-a", grants=[CONTENT_READ])
    interaction_id = _interaction(Session)
    session = Session()
    session.execute(
        sa.text("UPDATE interaction_contents SET input_json = '[{\"score\": NaN}]' WHERE interaction_id = :i"),
        {"i": interaction_id},
    )
    session.commit()
    session.close()

    assert client.get(f"/v1/logs/{interaction_id}/content?view=full", headers=headers).status_code == 500
    assert _audits(Session)[-1].outcome == "denied_corrupt"


def test_keys_api_returns_persisted_grants_and_never_the_implied_one(env):
    """The implication is applied at read time. Materialising it here would make
    it look like a third grant and let a later export check inherit it."""
    from app.services.key_service import KeyService

    _client, Session = env
    session = Session()
    try:
        from app.routes.keys import _key_to_dict

        _raw, api_key = KeyService(session).create_key(
            name="analyst", role="viewer", policy_id="policy-a", grants=[CONTENT_READ]
        )
        rendered = _key_to_dict(api_key)
        assert rendered["grants"] == [CONTENT_READ]
        assert MATCHES_READ not in rendered["grants"], "the implied grant was materialised"
    finally:
        session.close()
