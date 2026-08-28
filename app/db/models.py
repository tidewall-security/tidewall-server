"""SQLAlchemy ORM models for Tidewall.

The schema mirrors industry AI security platforms data model with these table groups:

**Policy configuration** (hierarchical):
    Policy → RuleSet → AccessRule

    A Policy is the top-level config unit.  Each policy has one or more
    RuleSets keyed by event_type ("input", "output", "tool_listing").
    Each RuleSet contains detector configs (JSON) and optional AccessRules
    that pre-filter requests before detectors run.

**Authentication**:
    APIKey — bearer tokens with role-based access (admin/viewer/api)
    RegistrationToken — one-time tokens for device self-registration
    Device / AccessToken — browser extension device management

**Event storage**:
    Interaction — one row per guard evaluation (the audit trail)
    Vault — JSON-encoded PII vaults for reversible redaction (/v1/unredact)
    ActivityLog — admin actions (policy changes, key creation, etc.)

**Settings**:
    GlobalPromptList — admin-curated benign/malicious prompt patterns
    ModelIntent — intent statements for conformance checking
    ExportTarget — webhook/syslog export destinations
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)
from sqlalchemy.types import JSON


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all Tidewall models."""

    pass


class Policy(Base):
    """Top-level policy — each API key is bound to one policy."""

    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    type: Mapped[str] = mapped_column(String, nullable=False, default="application")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_only: Mapped[bool] = mapped_column(Boolean, default=False)
    # What to do when a blocking/redacting detector cannot run. Persisted
    # because the enforcement decision must survive a restart and be settable
    # through the API — a value that lives only on the transient PolicyConfig
    # is unreachable from a normally constructed engine.
    on_detector_failure: Mapped[str] = mapped_column(String, nullable=False, default="report")
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    # Raw content capture. Off by default, so a fresh install retains no
    # prompts until an operator turns it on — the insecure state is never the
    # one you get by not reading the documentation.
    #
    # Inert until step 5: nothing writes interaction_contents yet, and the
    # setting is not writable through the API until the code that honours it
    # lands, so no state can claim capture is on while nothing captures.
    raw_content_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Null means no time expiry, which is the configured default. There is
    # deliberately no size cap.
    raw_content_retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    rule_sets: Mapped[list[RuleSet]] = relationship(back_populates="policy", cascade="all, delete-orphan")
    api_keys: Mapped[list[APIKey]] = relationship(back_populates="policy")


class RuleSet(Base):
    """Per-event-type detector configuration within a policy.

    A policy might have different detector settings for "input" vs "output"
    events.  The ``detectors`` JSON column stores the full detector config
    dict that gets passed to ScannerEngine.from_detectors().
    """

    __tablename__ = "rule_sets"
    __table_args__ = (UniqueConstraint("policy_id", "event_type"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    policy_id: Mapped[str] = mapped_column(String, ForeignKey("policies.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    detectors: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    report_only: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=None)

    policy: Mapped[Policy] = relationship(back_populates="rule_sets")
    access_rules: Mapped[list[AccessRule]] = relationship(
        back_populates="rule_set",
        cascade="all, delete-orphan",
        order_by="AccessRule.sort_order",
    )


class AccessRule(Base):
    """Pre-detector allow/block rules evaluated by condition matching.

    Evaluated in sort_order before any ML detectors run.  Conditions match
    on request metadata (user_id, app_id, source_ip, etc.).  A rule that
    blocks short-circuits the entire pipeline with zero detector cost.
    """

    __tablename__ = "access_rules"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    rule_set_id: Mapped[str] = mapped_column(String, ForeignKey("rule_sets.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    conditions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    then_action: Mapped[str] = mapped_column(String, nullable=False, default="continue")
    else_action: Mapped[str] = mapped_column(String, nullable=False, default="continue")
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    rule_set: Mapped[RuleSet] = relationship(back_populates="access_rules")


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, nullable=False)
    key_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    key_prefix: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="api")
    # Content grants, deliberately ORTHOGONAL to the role rather than implied
    # by it. An admin administers policies; that is not the same question as
    # whether they may read the prompts, and every product researched separates
    # the two. Empty means no content access, including for admin.
    #
    # Inert until step 6: nothing reads this yet.
    grants: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    policy_id: Mapped[str | None] = mapped_column(String, ForeignKey("policies.id", ondelete="SET NULL"), nullable=True)
    collector_type: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    policy: Mapped[Policy | None] = relationship(back_populates="api_keys")


class Interaction(Base):
    """One row per guard evaluation — the primary audit trail.

    Stores the full request context, detector results (as JSON), timing,
    and the final verdict.  Powers the dashboard's findings and visibility pages.
    """

    __tablename__ = "interactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    timestamp: Mapped[str] = mapped_column(String, nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    # NOT NULL: reads are scoped by this, so a null would make the row
    # invisible to every viewer — a silent audit gap rather than a loud one.
    # The writer stores the policy actually used to evaluate, not the caller's
    # binding, which may be null.
    policy_id: Mapped[str] = mapped_column(String, nullable=False)
    policy_name: Mapped[str] = mapped_column(String, nullable=False)
    api_key_id: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str | None] = mapped_column(String, nullable=True, default="allowed")
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    transformed: Mapped[bool] = mapped_column(Boolean, default=False)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    # Safe evidence only: detector, verdict, entity type and count. Never the
    # prompt, the reply, a matched value, a raw URL or an offset.
    #
    # Four columns were removed here rather than nulled. `summary` is one of
    # them and was the easiest to miss: it carried the matched access-rule name
    # and detector-derived strings, and was displayed *and searched* in the UI.
    # A nullable legacy column is an attractive sink that keeps stale code
    # compiling and makes schema inspection advertise retention that no longer
    # happens.
    evidence_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    evidence_schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Set by step 5 when raw content is captured for this event. False here,
    # so the reader can distinguish "not retained" from "withheld from you".
    content_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    app_id: Mapped[str | None] = mapped_column(String, nullable=True)
    user_id: Mapped[str | None] = mapped_column(String, nullable=True)
    llm_provider: Mapped[str | None] = mapped_column(String, nullable=True)
    model: Mapped[str | None] = mapped_column(String, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    device_id: Mapped[str | None] = mapped_column(String, nullable=True)

    __table_args__ = (
        Index("ix_interactions_policy_timestamp", "policy_id", "timestamp"),
        Index("ix_interactions_policy_status_timestamp", "policy_id", "status", "timestamp"),
        Index("ix_interactions_device_id", "device_id"),
    )


class InteractionContent(Base):
    """Raw prompt content, in a separate table behind a separate grant.

    Created inert by the same destructive migration that removed the content
    columns from ``interactions``, rather than by a second one over the same
    table. Nothing writes it until step 5 and nothing reads it until step 6.

    Separate rather than more columns, deliberately. Every product researched
    that retains this content separates it — Forcepoint keeps incident metadata
    in SQL Server and raw transactions in a filesystem repository reached with
    a distinct credential; Sentinel marks the table protected and denies by
    default. A separate table makes "who may read prompts" a different question
    from "who may read findings", which is the whole point of the tiering.
    """

    __tablename__ = "interaction_contents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    interaction_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("interactions.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    # The parent's policy, duplicated. The read path requires the credential's
    # policy, the interaction's policy and this column to be equal; a join would
    # prove the first two and assume the third. Detected on read and excluded in
    # SQL when it disagrees -- not prevented, because SQLite cannot express a
    # cross-table equality without a trigger.
    policy_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    # The prompt and the reply, and the exact matched values from the step 1
    # channel. Written only when the policy explicitly enables capture.
    input_json: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    output_json: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    matches_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    captured_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now, index=True)
    # Null means no time expiry, which is the configured default.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)


class ContentAccessAudit(Base):
    """Every read of raw content, recorded synchronously.

    Reading a prompt is the privileged act this design exists to gate, so it is
    audited where the read happens rather than inferred from request logs. It
    records who and what, never the content itself.
    """

    __tablename__ = "content_access_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    interaction_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    # Not a foreign key: the audit must outlive the row it describes, or
    # deleting the content would erase the record of who read it.
    api_key_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    # matches | full. Named tier from step 4; it carries exactly what a "view"
    # column would, so a synonym would only create a dual-write obligation.
    tier: Mapped[str] = mapped_column(String, nullable=False)
    policy_id: Mapped[str | None] = mapped_column(String, nullable=True)
    accessed_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=_now, index=True)
    # Nullable so any row written before this step survives.
    actor_role: Mapped[str | None] = mapped_column(String, nullable=True)
    # The authorization rule exercised -- the least-privilege grant sufficient
    # for the view, not the strongest one the caller held.
    grant_used: Mapped[str | None] = mapped_column(String, nullable=True)
    outcome: Mapped[str | None] = mapped_column(String, nullable=True)
    # Why a denied_scope was denied. Internal: the caller sees one uniform 404
    # for all four causes, and an operator investigating needs to know which.
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    # This access attempt's own correlation id, not the target interaction's
    # request_id -- that is already derivable from interaction_id.
    attempt_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    # The ASGI peer, never X-Forwarded-For: there is no trusted-proxy
    # configuration here, so a header would let a caller choose their own
    # audit attribution.
    source_ip: Mapped[str | None] = mapped_column(String, nullable=True)


class Vault(Base):
    """Persisted PII vault for reversible redaction.

    ``data`` is a JSON-encoded :class:`~app.vault.TidewallVault` payload
    containing the original PII values keyed by their placeholder tokens.
    The /v1/unredact endpoint loads the vault by ID (encoded in the
    fpe_context token) to recover original text.

    Note that in practice this column currently holds only *empty* vaults, and
    the payload format is plaintext. See :mod:`app.vault_manager` for why, and
    for the constraint that encryption must land in the same change as the
    persistence fix.
    """

    __tablename__ = "vaults"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class ActivityLog(Base):
    __tablename__ = "activity_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_now)
    actor: Mapped[str] = mapped_column(String, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    target_type: Mapped[str] = mapped_column(String, nullable=False)
    target_id: Mapped[str] = mapped_column(String, nullable=False)
    old_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    new_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class GlobalPromptList(Base):
    __tablename__ = "global_prompt_lists"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    list_type: Mapped[str] = mapped_column(String, nullable=False)  # "benign" | "malicious"
    pattern: Mapped[str] = mapped_column(String, nullable=False)
    match_type: Mapped[str] = mapped_column(
        String, nullable=False, default="substring"
    )  # "substring" | "regex" | "exact"
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class ExportTarget(Base):
    __tablename__ = "export_targets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, nullable=False)
    type: Mapped[str] = mapped_column(String, nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    format: Mapped[str] = mapped_column(String, nullable=False, default="ocsf")
    events: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    # Content export is off unless a destination was deliberately marked for it.
    #
    # NOT an independent consent, and calling it one would be theatre: the same
    # admin can create the target, set this, and hold the export grant. It is an
    # explicit, default-off safety interlock -- content cannot leave to a
    # destination nobody marked for it. A real second consent would need a
    # separate approver, a durable approval with expiry and revocation, and
    # separation of duties; that is a product workflow, not a column, and is
    # not in this step.
    allow_content_export: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Scope, because a global boolean silently approves every policy and both
    # projections. A target approved for one policy is not approved for another,
    # and one approved for matches is not approved for full.
    content_export_policy_id: Mapped[str | None] = mapped_column(String, nullable=True)
    content_export_views: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class ContentExportAttempt(Base):
    """One attempt to send one interaction's content to one destination.

    Written as ``pending`` and committed BEFORE any I/O, so a crash is visible
    as pending rather than misrecorded. An ``exported``-then-``export_failed``
    pair would leave a misleading success row and a correlation that only works
    if the process survives to write the second one -- which is exactly the case
    that matters.

    Nothing here retries. Retrying an export whose delivery is unknown is how
    one disclosure becomes two.
    """

    __tablename__ = "content_export_attempts"

    attempt_id: Mapped[str] = mapped_column(String, primary_key=True)
    interaction_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    policy_id: Mapped[str] = mapped_column(String, nullable=False)
    target_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    api_key_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    actor_role: Mapped[str | None] = mapped_column(String, nullable=True)
    view: Mapped[str] = mapped_column(String, nullable=False)
    grant_used: Mapped[str | None] = mapped_column(String, nullable=True)

    state: Mapped[str] = mapped_column(String, nullable=False)
    # Null for anything that never got a status -- a refused connection, a DNS
    # failure -- and an HTTP status otherwise.
    transport_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # A size is a weak signal but a real one, and reconciling a transfer without
    # it is guesswork. The only measurement of the content kept anywhere.
    payload_bytes: Mapped[int] = mapped_column(Integer, nullable=False)

    # The digest, never the key: a caller-supplied correlator can be
    # credential-like. Scoped to the credential, because global uniqueness would
    # let one admin's key collide with or probe another's.
    idempotency_key_digest: Mapped[str | None] = mapped_column(String, nullable=True)
    # Everything that fixes the bytes or the authority. Target CONFIG is
    # deliberately absent: replay means the original attempt, and rebuilding a
    # result under current configuration would report something that never
    # happened.
    fingerprint: Mapped[str] = mapped_column(String, nullable=False)

    # Where it went. target_id alone is not evidence: a URL can be edited or the
    # target deleted, and then the row points at a destination that no longer
    # describes the disclosure.
    destination_host: Mapped[str] = mapped_column(String, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    # The validated set, which is what records where this could have gone. One
    # eventual peer does not.
    destination_addrs: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    # Known only after I/O, and not at all when every pinned address failed.
    destination_addr: Mapped[str | None] = mapped_column(String, nullable=True)
    target_config_digest: Mapped[str] = mapped_column(String, nullable=False)

    # The process that reserved it. The sweep abandons a pending row only when
    # this is not the running process's, which the database lock makes sound.
    boot_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("api_key_id", "idempotency_key_digest", name="uq_content_export_idempotency"),
        CheckConstraint(
            "state IN ('pending','succeeded','failed','indeterminate','abandoned_indeterminate')",
            name="ck_content_export_state",
        ),
        CheckConstraint(
            "(state = 'pending' AND settled_at IS NULL AND transport_status IS NULL) "
            "OR (state != 'pending' AND settled_at IS NOT NULL)",
            name="ck_content_export_settlement",
        ),
        CheckConstraint(
            "transport_status IS NULL OR (transport_status >= 100 AND transport_status <= 599)",
            name="ck_content_export_status_range",
        ),
    )


class ContentExportReconciliation(Base):
    """An operator's correction, appended.

    The attempt's own state is the original observation and is never edited. The
    EFFECTIVE state is the reconciliation with the highest id -- by monotonic
    integer, not timestamp, because two records written in the same clock tick
    would otherwise be unordered.
    """

    __tablename__ = "content_export_reconciliations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attempt_id: Mapped[str] = mapped_column(
        String, ForeignKey("content_export_attempts.attempt_id"), nullable=False, index=True
    )
    from_state: Mapped[str] = mapped_column(String, nullable=False)
    to_state: Mapped[str] = mapped_column(String, nullable=False)
    # Points at something outside this system -- a receiver's log, a ticket.
    # Never content, and bounded.
    evidence: Mapped[str] = mapped_column(String, nullable=False)
    reconciled_by: Mapped[str | None] = mapped_column(String, nullable=True)
    reconciled_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "to_state IN ('succeeded','failed','indeterminate')",
            name="ck_content_export_reconciliation_to",
        ),
    )


class ContentExportNote(Base):
    """What happened on a path that does not own the attempt row.

    Best effort: a note is evidence ABOUT an export, not a precondition of one,
    so failing to write one degrades to a log and never changes the response.
    That is the opposite direction from the attempt row, deliberately -- the row
    governs whether content leaves, and a note only describes what happened
    after it already did.
    """

    __tablename__ = "content_export_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attempt_id: Mapped[str] = mapped_column(
        String, ForeignKey("content_export_attempts.attempt_id"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String, nullable=False)
    # A status, a phase, an exception type. Never content, a response body, or a
    # URL -- a query string can carry a secret.
    detail: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "kind IN ('settlement_lost','body_read_failed','settlement_commit_failed','cleanup_failed')",
            name="ck_content_export_note_kind",
        ),
    )


class ModelIntent(Base):
    __tablename__ = "model_intent"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str | None] = mapped_column(String, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class RegistrationToken(Base):
    __tablename__ = "registration_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, nullable=False)
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    token_prefix: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    # Mandatory. An enrolment key with no deadline is a permanent capability to
    # create devices, and the containment story for a leak is then only
    # "somebody eventually notices".
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # None means uncapped, which is legitimate for a fleet key whose expiry is
    # doing the bounding. `uses` is incremented by a conditional UPDATE and
    # never by a read-modify-write: SQLite has no row locks, so the guard has
    # to live in the WHERE clause.
    max_uses: Mapped[int | None] = mapped_column(Integer, nullable=True)
    uses: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    # False by default: a key that is sufficient on its own is a key whose leak
    # is immediately a working device. True exists for fleet deployment where
    # the delivery channel is already trusted, which is why it is set per key
    # and never globally -- and why a pre-authorized key is worth protecting
    # more carefully than an ordinary one.
    pre_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")
    # Soft revocation. Hard deletion takes the lineage with it -- reg_token_id
    # is SET NULL on delete -- and a revoked key is precisely when knowing which
    # devices came from it matters most.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Scope an enrolling device inherits. Without this a registration token
    # conferred no policy at all — the middleware set policy_id = None — so
    # enrolled devices had no binding to constrain them.
    #
    # RESTRICT, not SET NULL: guard reads a null binding as "use the default
    # policy", so nulling this on delete would silently move the token's future
    # devices onto rules nobody chose for them. The service refuses the delete
    # for a readable message, but the count-then-delete it does is not atomic —
    # this is what actually holds.
    policy_id: Mapped[str | None] = mapped_column(String, ForeignKey("policies.id", ondelete="RESTRICT"), nullable=True)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    # UUID the client generates once and stores. This is the device's identity.
    # Clients must generate it with a CSPRNG; the server validates the form and
    # cannot establish that the value was actually random.
    installation_id: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    # Advisory metadata only, deliberately NOT unique. It was previously the
    # unique key AND the lookup used to authorise a refresh, which is what made
    # P0-11 possible: a client-supplied, guessable value is neither identity
    # nor proof. Being unique also let one client deny enrolment to another
    # simply by claiming its fingerprint.
    fingerprint: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    device_name: Mapped[str] = mapped_column(String, nullable=False)
    user_name: Mapped[str] = mapped_column(String, nullable=False)
    user_email: Mapped[str] = mapped_column(String, nullable=False)
    browser: Mapped[str] = mapped_column(String, nullable=False, default="")
    os: Mapped[str] = mapped_column(String, nullable=False, default="")
    ext_version: Mapped[str] = mapped_column(String, nullable=False, default="")
    reg_token_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("registration_tokens.id", ondelete="SET NULL"), nullable=True
    )
    # A SNAPSHOT, not a foreign key. The FK above is SET NULL on delete, so
    # deleting a leaked key silently makes every device it created
    # unattributable -- and deleting the key is an administrator's first
    # instinct on discovering the leak. Written once at enrolment and never
    # updated: it records which key this device came from, which cannot change.
    reg_token_prefix: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    # RESTRICT for the same reason as the registration token's: a device's scope
    # is fixed at enrolment, and deleting its policy must not quietly reassign
    # it to the default one.
    policy_id: Mapped[str | None] = mapped_column(String, ForeignKey("policies.id", ondelete="RESTRICT"), nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="active")
    # Displayed by the enrolling client and matched by an administrator before
    # activation. Every other field on this row is supplied by the claimant, so
    # none of them can decide approval: a key holder copies the expected user,
    # email, device name, browser and OS and the row looks exactly like a real
    # one. Cleared on approval so it cannot be replayed.
    confirmation_code: Mapped[str | None] = mapped_column(String, nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class DeviceTombstone(Base):
    """Durable evidence that a device was revoked.

    Outlives the device row and every credential it held. "Stop permanently" is
    only true for as long as the evidence lasts: revocation deletes the
    credentials, so a client that comes back later presents something unknown
    and is told to re-enrol -- which is the recovery path, and undoes the
    revocation by itself.

    No foreign key to devices. It must survive that row's deletion, which is
    the case it exists for.
    """

    __tablename__ = "device_tombstones"

    device_id: Mapped[str] = mapped_column(String, primary_key=True)
    installation_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    # Set by an explicit administrator action. Hashed: it is a credential.
    #
    # Single-use decides who WINS a race; it does not decide who is ENTITLED.
    # A bare "this installation may enrol again" flag is claimable by whoever
    # asks first, including the party the revocation was aimed at.
    recovery_secret_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class DeviceRefreshToken(Base):
    """Long-lived, non-rotating, single-purpose credential for one device.

    Its own table rather than a column on AccessToken: the two have different
    lifetimes, different reach and different revocation rules, and sharing a
    table invites a query that forgets which kind it is holding.

    It does not rotate. Rotation cannot both survive a lost response and detect
    reuse -- a client retrying after a committed-but-lost rotation is
    indistinguishable from a thief -- so every variant either locks out real
    clients or fails to catch real theft. Under a non-hostile host a credential
    that cannot lock its owner out is worth more than one that pretends to
    catch a thief it cannot catch.

    The cost, stated: a stolen refresh token is usable until it expires or an
    administrator revokes it.
    """

    __tablename__ = "device_refresh_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    device_id: Mapped[str] = mapped_column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AccessToken(Base):
    __tablename__ = "access_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    device_id: Mapped[str] = mapped_column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    # Set when this token is superseded by a rotation, so the replacement can
    # be traced and the old one expired with a short overlap rather than
    # deleted outright — an in-flight request must not fail because a refresh
    # happened to land first.
    replaced_by_id: Mapped[str | None] = mapped_column(String, nullable=True)
