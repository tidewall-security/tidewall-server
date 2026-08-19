"""The audited one-record content API.

The only door to retained prompt content, with three independent locks: a grant
that no role implies, an exact policy match, and an audit record that must land
before anything is disclosed.

Step 5's rule was that optional capture must never change the security
decision. This inverts it deliberately: **the access audit is a precondition of
disclosure**. Capture passively observes a decision already made, so its failure
must not propagate; this audit records a privileged disclosure that has not
happened yet, so its failure must prevent it.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from fastapi import APIRouter, Request, Response

from app.auth.grants import allows_view, grant_for
from app.db.models import ContentAccessAudit, Interaction, InteractionContent
from app.services.safe_logging import report

logger = logging.getLogger(__name__)

router = APIRouter()

CONTENT_PATH_RE = r"^/v1/logs/[^/]+/content$"

#: SQLAlchemy's SQLite DateTime bind processor writes exactly this, for both
#: aware and naive inputs: 26 characters, zero-padded, naive UTC. Fixed width is
#: what makes SQLite's lexicographic comparison chronological, which is what the
#: expiry CASE in the query relies on. A value in any other shape did not come
#: from this application.
_STORED_TIMESTAMP = "%Y-%m-%d %H:%M:%S.%f"

_MAX_ID = 2**63 - 1

# Stored audit outcomes.
AUTHORIZED = "authorized"
DENIED_GRANT = "denied_grant"
DENIED_SCOPE = "denied_scope"
DENIED_CORRUPT = "denied_corrupt"

# Why a denied_scope was denied. Internal: the caller gets one uniform 404 for
# all four, and an operator investigating needs to know which.
NO_SUCH_INTERACTION = "no_such_interaction"
NO_CONTENT_ROW = "no_content_row"
POLICY_MISMATCH = "policy_mismatch"
EXPIRED = "expired"

#: Audit writes that could not be made durable, since process start.
#:
#: There is no metrics system in this application, so this is a process counter
#: whose running total is included in each failure record -- log-based alerting
#: is what an operator actually has today. A metrics endpoint is a follow-up,
#: and saying so is better than describing a counter nobody can scrape.
_audit_failures = 0


def audit_failure_count() -> int:
    """How many audit writes have failed since process start."""
    return _audit_failures


_NO_STORE = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


class _Corrupt(Exception):
    """Stored content is not what this system writes. Server-side corruption."""


def _json(status: int, body: dict[str, Any]) -> Response:
    """One constructor for every response, so error bodies cannot drift apart.

    Canonical encoding because the non-enumerability test compares body bytes:
    key order is the caller's, separators are fixed, non-ASCII is emitted as
    UTF-8 rather than escaped, and non-finite numbers are refused rather than
    written as the tokens Python's json accepts but JSON does not.
    """
    encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return Response(
        content=encoded,
        status_code=status,
        media_type="application/json",
        headers=dict(_NO_STORE),
    )


def _error(status: int, detail: str) -> Response:
    return _json(status, {"detail": detail})


# ---------------------------------------------------------------------------
# Parsing and validation
# ---------------------------------------------------------------------------


def _parse_stored_timestamp(raw: object) -> datetime:
    """Parse a stored timestamp, accepting only the canonical form.

    Only the exact form SQLAlchemy's SQLite DateTime writes. A parseable but
    non-canonical value -- one carrying a UTC offset, say -- can sort
    differently from its chronological position, so the query's expiry CASE and
    this parse could disagree and produce a 200 full of nulls for a row that is
    not actually expired. Restricting to the written form makes them provably
    equivalent, and anything else did not come from here.
    """
    if not isinstance(raw, str):
        raise _Corrupt("timestamp is not text")
    try:
        return datetime.strptime(raw, _STORED_TIMESTAMP).replace(tzinfo=UTC)
    except ValueError as exc:
        raise _Corrupt("timestamp is not in the stored form") from exc


def _render(moment: datetime) -> str:
    """One rendering, because "ISO-8601 UTC" does not determine a unique body.

    Z rather than +00:00, and isoformat's own fractional-second behaviour rather
    than a hand-rolled format string.
    """
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _decode(raw: object, field: str) -> Any:
    """Decode a payload column that the query handed back as text.

    The columns are cast to TEXT in SQL precisely so nothing is parsed while the
    row is being fetched: SQLAlchemy's JSON result processor would raise there,
    before this endpoint could classify the row or write its denied_corrupt
    audit. Decoding here puts the failure inside the boundary that can.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise _Corrupt(f"{field} is not text")
    try:
        # Python's json accepts NaN and Infinity, which are not JSON. Under an
        # application/json contract, emitting a non-standard token or silently
        # coercing it are both worse than refusing.
        return json.loads(raw, parse_constant=_reject_constant)
    except (ValueError, _Corrupt) as exc:
        raise _Corrupt(f"{field} is not valid JSON") from exc


def _reject_constant(name: str) -> Any:
    raise _Corrupt(f"non-finite number {name}")


def _strict_int(value: object, *, minimum: int) -> int:
    """An integer, not a bool. ``bool`` is an ``int`` in Python, and Pydantic
    coerces by default, so ``{"occurrences": "1"}`` had two defensible answers."""
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise _Corrupt("expected an integer")
    return value


def _strict_str(value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise _Corrupt("expected a string")
    return value


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return _strict_str(value, allow_empty=True)


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------
#
# Built field by field. Every field is always present and null carries the
# meaning, so there is no absent-versus-null rule to get wrong -- and SQL NULL
# and JSON null are deliberately not distinguished, because the difference is
# only how the row happened to be written.


_MATCH_KEYS = {"detector", "match_type", "rule_id", "source", "value", "occurrences"}
_SOURCE_KEYS = {"kind", "index", "field", "role"}


def _match_group(raw: object) -> dict[str, Any]:
    """One stored match. Exact keys required.

    Unlike the caller's messages, this system wrote these itself, so an
    unexpected shape is tampering or version skew rather than a permissive
    caller.
    """
    if not isinstance(raw, dict) or set(raw) != _MATCH_KEYS:
        raise _Corrupt("match group has unexpected keys")
    source = raw["source"]
    if not isinstance(source, dict) or set(source) != _SOURCE_KEYS:
        raise _Corrupt("match source has unexpected keys")
    return {
        "detector": _strict_str(raw["detector"]),
        "match_type": _strict_str(raw["match_type"]),
        "rule_id": _optional_str(raw["rule_id"]),
        "source": {
            # Any non-empty string, deliberately. These vocabularies can grow
            # inside schema version 1, they drive no authorization, parsing or
            # control flow, and rejecting evidence over a vocabulary addition
            # would destroy readable forensic data to no purpose.
            "kind": _strict_str(source["kind"]),
            "index": _strict_int(source["index"], minimum=0),
            "field": _strict_str(source["field"]),
            "role": _optional_str(source["role"]),
        },
        "value": _strict_str(raw["value"], allow_empty=True),
        "occurrences": _strict_int(raw["occurrences"], minimum=1),
    }


def _matches_block(raw: object) -> dict[str, Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "matches"}:
        raise _Corrupt("matches has unexpected keys")
    version = raw["schema_version"]
    # Exactly the JSON integer 1. Not true, not 1.0, not "1". A future writer
    # that bumps the version must land with a reader that understands it;
    # rendering a version this code does not know would be guessing at the
    # meaning of forensic evidence.
    if isinstance(version, bool) or version != 1 or not isinstance(version, int):
        raise _Corrupt("unsupported matches schema version")
    groups = raw["matches"]
    if not isinstance(groups, list):
        raise _Corrupt("matches is not a list")
    return {"schema_version": 1, "matches": [_match_group(g) for g in groups]}


def _list_or_none(raw: object, field: str) -> list[Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise _Corrupt(f"{field} is not a list")
    return raw


def _split_input(raw: object) -> tuple[list[Any] | None, list[Any] | None]:
    """Messages and tools out of the stored input.

    build_content() writes the wrapper whenever tools were supplied at all,
    including an empty list, and the bare message list otherwise. There is no
    tools column to read instead.
    """
    if raw is None:
        return None, None
    if isinstance(raw, list):
        return raw, None
    if isinstance(raw, dict):
        if set(raw) != {"messages", "tools"}:
            raise _Corrupt("input wrapper has unexpected keys")
        return _list_or_none(raw["messages"], "messages"), _list_or_none(raw["tools"], "tools")
    raise _Corrupt("input is neither a message list nor the wrapper")


def _select(interaction_id: int, policy_id: str, now: datetime) -> sa.Select:
    """One policy-scoped statement. Everything the caller can observe comes from it.

    Three properties it has to carry at once:

    - **Uniform 404.** ``Interaction.id`` and the credential's policy are
      constrained together, so an interaction in another policy is
      indistinguishable from one that does not exist -- to the query, not merely
      to the control flow above it. There is no unscoped load, so no moment
      exists in which the wrong row is in memory.
    - **Classification.** The outer join plus the EXISTS marker separates "no
      content row" from "content row whose duplicated policy disagrees", which
      an inner join collapses. The marker returns a boolean and selects no
      column of the offending row: no mismatched payload is ever loaded.
    - **No fetch-time decoding.** Payload columns are cast to TEXT and
      timestamps likewise, so nothing is parsed while the row is fetched. A
      malformed row would otherwise raise inside SQLAlchemy's result processing,
      before this endpoint could classify it or write its audit.
    """
    c = sa.orm.aliased(InteractionContent)
    live = sa.or_(c.expires_at.is_(None), c.expires_at > now)

    any_content = (
        sa.select(sa.literal(1))
        .select_from(InteractionContent)
        .where(InteractionContent.interaction_id == Interaction.id)
        .exists()
    )

    return (
        sa.select(
            Interaction.id.label("interaction_id"),
            c.id.label("content_id"),
            sa.cast(c.captured_at, sa.Text).label("captured_raw"),
            sa.cast(c.expires_at, sa.Text).label("expires_raw"),
            # Suppressed in the database for an expired row, so expired bytes
            # never enter the process at all.
            sa.case((live, sa.cast(c.input_json, sa.Text))).label("input_raw"),
            sa.case((live, sa.cast(c.output_json, sa.Text))).label("output_raw"),
            sa.case((live, sa.cast(c.matches_json, sa.Text))).label("matches_raw"),
            any_content.label("any_content"),
        )
        .select_from(Interaction)
        .outerjoin(c, sa.and_(c.interaction_id == Interaction.id, c.policy_id == policy_id))
        .where(Interaction.id == interaction_id, Interaction.policy_id == policy_id)
    )


def _audit(
    session: Any,
    *,
    attempt_id: str,
    api_key_id: str | None,
    actor_role: str | None,
    policy_id: str | None,
    interaction_id: int | None,
    view: str,
    outcome: str,
    reason: str | None,
    grant_used: str | None,
    source_ip: str | None,
) -> None:
    session.add(
        ContentAccessAudit(
            interaction_id=interaction_id or 0,
            api_key_id=api_key_id,
            tier=view,
            policy_id=policy_id,
            actor_role=actor_role,
            grant_used=grant_used,
            outcome=outcome,
            reason=reason,
            attempt_id=attempt_id,
            source_ip=source_ip,
        )
    )
    session.commit()


@router.get("/v1/logs/{interaction_id}/content")
async def read_content(request: Request) -> Response:
    """Read the retained content of one interaction.

    Declares no typed parameters on purpose. A typed path or query parameter
    lets FastAPI produce a 422 before any application code runs, and dependency
    resolution is not a sequencing language -- so ``interaction_id`` and ``view``
    are read as raw strings and one ordered helper does everything. The order is
    then a property of this code rather than of the framework's resolution.

    The outer catch is a last resort only. Audit failures are handled beneath it
    so they cannot be translated into a 500.
    """
    try:
        return await _authorize_and_read(request)
    except Exception as exc:
        report(logger, "error", "content read failed unexpectedly", exc)
        return _error(500, "Internal error")


async def _authorize_and_read(request: Request) -> Response:
    # 1. Authentication has already happened in middleware.
    # 2. Syntax. Before authorization, and before any query, so a malformed id
    #    cannot reach the driver and a bad view cannot become FastAPI's 422.
    raw_view = request.query_params.getlist("view")
    if len(raw_view) != 1:
        # Rejecting duplicates rather than silently taking one, so a proxy and
        # this application cannot disagree about which representation was
        # authorized.
        return _error(400, "Exactly one 'view' parameter is required")
    view = raw_view[0]
    if view not in ("matches", "full"):
        return _error(400, "view must be 'matches' or 'full'")

    raw_id = request.path_params.get("interaction_id", "")
    if not isinstance(raw_id, str) or not raw_id.isdigit():
        return _error(400, "interaction_id must be a positive integer")
    interaction_id = int(raw_id)
    if interaction_id < 1 or interaction_id > _MAX_ID:
        # Checked before the query: a Python integer larger than SQLite can
        # hold would otherwise reach the driver.
        return _error(400, "interaction_id is out of range")

    # 3. Authorization on properties that do not depend on the id, so the answer
    #    is identical for every id and leaks nothing.
    role = getattr(request.state, "role", None)
    grants: frozenset[str] = getattr(request.state, "grants", frozenset())
    policy_id = getattr(request.state, "policy_id", None)
    api_key_id = getattr(request.state, "api_key_id", None)

    attempt_id = uuid.uuid4().hex
    # The ASGI peer, never X-Forwarded-For: there is no trusted-proxy
    # configuration here, so a header would let a caller pick their own
    # audit attribution.
    source_ip = request.client.host if request.client else None

    session_factory = request.app.state.session_factory

    def audit(outcome: str, *, reason: str | None, grant_used: str | None, interaction: int | None) -> bool:
        """Record the decision. Returns whether it landed.

        The boundary covers acquiring the session, writing, rolling back and
        closing. Acquisition sat outside it and a factory failure reached the
        endpoint's last-resort catch -- turning a required 503 into a 500 on the
        authorized path, and replacing a denial with a 500 on the denied one.
        Nothing about auditing may decide the status except in the two ways the
        design specifies.
        """
        global _audit_failures
        session = None
        try:
            session = session_factory()
            _audit(
                session,
                attempt_id=attempt_id,
                api_key_id=api_key_id,
                actor_role=role,
                policy_id=policy_id,
                interaction_id=interaction,
                view=view,
                outcome=outcome,
                reason=reason,
                grant_used=grant_used,
                source_ip=source_ip,
            )
            return True
        except Exception as exc:
            _audit_failures += 1
            # Rolled back before anything else. A poisoned session is never
            # reused to emit a second audit.
            if session is not None:
                try:
                    session.rollback()
                except Exception:
                    pass
            # Bounded and after the rollback: identifiers and the outcome that
            # was meant to be stored, no exception text and nothing derived from
            # content. Evidence that the durable audit could not be written --
            # not a substitute for it.
            report(
                logger,
                "error",
                f"content access audit failed: attempt={attempt_id} key={api_key_id} "
                f"outcome={outcome} failures_since_start={_audit_failures}",
                exc,
            )
            return False
        finally:
            # Also inside the boundary: a close failure after a successful
            # commit would otherwise escape and turn an authorized read into a
            # 500 that the caller cannot distinguish from a real fault.
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass

    if role is None:
        return _error(401, "Not authenticated")
    if role not in ("viewer", "admin") or not policy_id or not allows_view(grants, view):
        # Denial audit is best effort. Converting a denial to 503 would restore
        # no audit, deny nothing further, and add a second oracle.
        audit(DENIED_GRANT, reason=None, grant_used=None, interaction=interaction_id)
        return _error(403, "Content access requires an explicit grant")

    grant_used = grant_for(view)
    now = datetime.now(UTC)

    def deny_scope(reason: str) -> Response:
        audit(DENIED_SCOPE, reason=reason, grant_used=grant_used, interaction=interaction_id)
        return _error(404, "Not found")

    session = session_factory()
    try:
        # 4. One policy-scoped statement.
        row = session.execute(_select(interaction_id, policy_id, now)).first()
        if row is None:
            return deny_scope(NO_SUCH_INTERACTION)
        if row.content_id is None:
            return deny_scope(POLICY_MISMATCH if row.any_content else NO_CONTENT_ROW)

        try:
            # 5. Expiry, from the parsed value rather than from the SQL
            #    comparison. SQL cannot both classify expiry and vouch that the
            #    stored value is a valid datetime: a malformed "0000" sorts as
            #    expired and would return 404 unparsed, while another malformed
            #    value sorts later and would return 500. Parsing first makes the
            #    answer the same either way.
            expires_at = None if row.expires_raw is None else _parse_stored_timestamp(row.expires_raw)
            if expires_at is not None and expires_at <= now:
                # captured_at is deliberately not parsed here, so an expired row
                # with a malformed one is still 404.
                return deny_scope(EXPIRED)

            # 6. Build and serialise the whole projection before the audit. A
            #    failure after a committed "authorized" row would record a
            #    disclosure that never happened.
            body: dict[str, Any] = {
                "interaction_id": row.interaction_id,
                "view": view,
                "captured_at": _render(_parse_stored_timestamp(row.captured_raw)),
                "expires_at": None if expires_at is None else _render(expires_at),
            }
            if view == "full":
                # Only the full view decodes input and output. Corruption in a
                # column this view does not serve cannot fail a matches read,
                # and a caller without the full grant should not have the prompt
                # decoded on their behalf.
                messages, tools = _split_input(_decode(row.input_raw, "input"))
                body["messages"] = messages
                body["tools"] = tools
                body["output"] = _list_or_none(_decode(row.output_raw, "output"), "output")
            body["matches"] = _matches_block(_decode(row.matches_raw, "matches"))

            encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        except (_Corrupt, ValueError) as exc:
            report(logger, "error", "stored content is corrupt", exc)
            audit(DENIED_CORRUPT, reason=None, grant_used=grant_used, interaction=interaction_id)
            return _error(500, "Stored content is unreadable")
    finally:
        # Guarded for the same reason the audit session's close is: by this
        # point the projection is already built, and failing to release a
        # session is not a reason to turn an answered request into a 500 the
        # caller cannot distinguish from a real fault.
        try:
            session.close()
        except Exception as exc:
            report(logger, "error", "could not close the content read session", exc)

    # 7. The audit is the precondition. No content without it.
    if not audit(AUTHORIZED, reason=None, grant_used=grant_used, interaction=interaction_id):
        return _error(503, "Content access audit unavailable")

    # 8. Already-serialised bytes. No ORM object is touched after the commit.
    return Response(
        content=encoded,
        status_code=200,
        media_type="application/json",
        headers=dict(_NO_STORE),
    )
