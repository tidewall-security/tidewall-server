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
    FPESettings — format-preserving encryption key (singleton row)
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
    DateTime,
    Float,
    ForeignKey,
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
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
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
    policy_id: Mapped[str | None] = mapped_column(String, nullable=True)
    policy_name: Mapped[str] = mapped_column(String, nullable=False)
    api_key_id: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str | None] = mapped_column(String, nullable=True, default="allowed")
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    transformed: Mapped[bool] = mapped_column(Boolean, default=False)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    input_messages: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    output_messages: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    detectors_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    app_id: Mapped[str | None] = mapped_column(String, nullable=True)
    user_id: Mapped[str | None] = mapped_column(String, nullable=True)
    llm_provider: Mapped[str | None] = mapped_column(String, nullable=True)
    model: Mapped[str | None] = mapped_column(String, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    device_id: Mapped[str | None] = mapped_column(String, nullable=True)


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


class FPESettings(Base):
    __tablename__ = "fpe_settings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default="singleton")
    key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    default_tweak: Mapped[str | None] = mapped_column(String, nullable=True)
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
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    fingerprint: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    device_name: Mapped[str] = mapped_column(String, nullable=False)
    user_name: Mapped[str] = mapped_column(String, nullable=False)
    user_email: Mapped[str] = mapped_column(String, nullable=False)
    browser: Mapped[str] = mapped_column(String, nullable=False, default="")
    os: Mapped[str] = mapped_column(String, nullable=False, default="")
    ext_version: Mapped[str] = mapped_column(String, nullable=False, default="")
    reg_token_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("registration_tokens.id", ondelete="SET NULL"), nullable=True
    )
    policy_id: Mapped[str | None] = mapped_column(String, ForeignKey("policies.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="active")
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class AccessToken(Base):
    __tablename__ = "access_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    device_id: Mapped[str] = mapped_column(String, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
