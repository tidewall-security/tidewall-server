"""Scope native callbacks to a live collector and a separate, revocable session capability."""

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.auth.key_utils import hash_key
from app.db.models import (
    AgentSession,
    Device,
    DeviceTombstone,
    NativePromptGrant,
    NativePromptObservation,
    NativePromptPolicyConfig,
    Policy,
)
from app.native_prompt import NativeError, NativeGrantIssued, NativeGrantRequest, NativeMetadata, NativePolicySettings
from app.services.agent_event_service import DETAIL_LIFETIME, _retire_session
from app.services.collector_identity import authorize_collector
from app.services.native_prompt_policy import NativePolicyConfig, NativePolicyUnsupported, freeze_native_policy
from app.utils import as_utc


@dataclass(frozen=True)
class NativePrincipal:
    device_id: str
    policy_id: str
    collector_token_hash: str = field(repr=False)
    capability_hash: str = field(repr=False)
    grant_id: str
    grant_generation: int
    policy_generation: int
    session_token: str = field(repr=False)
    profile: str
    capture_allowed: bool


def read_native_config(session: Session, policy_id: str) -> NativePolicyConfig:
    row = session.execute(
        select(
            NativePromptPolicyConfig.enabled,
            NativePromptPolicyConfig.profile,
            NativePromptPolicyConfig.threshold,
            NativePromptPolicyConfig.generation,
        ).where(NativePromptPolicyConfig.policy_id == policy_id)
    ).one_or_none()
    return NativePolicyConfig(*row) if row else NativePolicyConfig()


def check_admin_scope(actor_policy_id: str | None, policy_id: str) -> None:
    if actor_policy_id is not None and actor_policy_id != policy_id:
        raise NativeError("unauthorized", 403)


def configure_native(
    session: Session, policy_id: str, settings: NativePolicySettings, actor_policy_id: str | None
) -> NativePolicyConfig:
    check_admin_scope(actor_policy_id, policy_id)
    if session.scalar(select(Policy.id).where(Policy.id == policy_id)) is None:
        raise NativeError("invalid_request", 404)
    old = read_native_config(session, policy_id)
    changed = (settings.enabled, settings.profile, settings.threshold) != (old.enabled, old.profile, old.threshold)
    generation = max(1, old.generation + int(changed))
    new = NativePolicyConfig(settings.enabled, settings.profile, settings.threshold, generation)
    if new.enabled:
        try:
            freeze_native_policy(session, policy_id, new)
        except NativePolicyUnsupported:
            raise NativeError("policy_unsupported", 409) from None
    session.merge(
        NativePromptPolicyConfig(
            policy_id=policy_id,
            enabled=new.enabled,
            profile=new.profile,
            threshold=new.threshold,
            generation=new.generation,
        )
    )
    return new


def _native_session_exists(
    session: Session, session_id: str, device_id: str, policy_id: str, token: str, now: datetime
) -> bool:
    obs = NativePromptObservation
    return bool(
        session.scalar(
            select(
                select(obs.event_id)
                .join(AgentSession, AgentSession.session_id == obs.session_id)
                .where(
                    obs.device_id == device_id,
                    obs.policy_id == policy_id,
                    obs.session_id == session_id,
                    obs.session_token == token,
                    AgentSession.native_session_token == token,
                    obs.expires_at > now,
                )
                .exists()
            )
        )
    )


def issue_native_grant(
    session: Session, request: NativeGrantRequest, actor_policy_id: str | None, *, now: datetime
) -> NativeGrantIssued:
    device = session.execute(
        select(
            Device.id,
            Device.policy_id,
            Device.purpose,
            Device.status,
            Device.collector_approved_at,
            DeviceTombstone.device_id.label("tombstone"),
        )
        .outerjoin(DeviceTombstone, DeviceTombstone.device_id == Device.id)
        .where(Device.id == request.device_id)
    ).one_or_none()
    if not device or not device.policy_id:
        raise NativeError("unauthorized", 403)
    check_admin_scope(actor_policy_id, device.policy_id)
    if (
        device.purpose != "collector_write"
        or device.status != "active"
        or not device.collector_approved_at
        or device.tombstone
    ):
        raise NativeError("unauthorized", 403)
    config = read_native_config(session, device.policy_id)
    if not config.enabled:
        raise NativeError("policy_unsupported", 409)
    try:
        freeze_native_policy(session, device.policy_id, config)
    except NativePolicyUnsupported:
        raise NativeError("policy_unsupported", 409) from None
    if request.capture_allowed and (
        not request.session_id
        or not _native_session_exists(
            session, request.session_id, device.id, device.policy_id, request.session_token, now
        )
    ):
        raise NativeError("unauthorized", 403)
    scope = (
        NativePromptGrant.device_id == device.id,
        NativePromptGrant.policy_id == device.policy_id,
        NativePromptGrant.session_token == request.session_token,
        NativePromptGrant.native_profile == request.native_profile,
    )
    generation = (session.scalar(select(func.max(NativePromptGrant.grant_generation)).where(*scope)) or 0) + 1
    session.execute(
        update(NativePromptGrant).where(*scope, NativePromptGrant.revoked_at.is_(None)).values(revoked_at=now)
    )
    secret = secrets.token_urlsafe(32)
    grant = NativePromptGrant(
        device_id=device.id,
        policy_id=device.policy_id,
        session_token=request.session_token,
        native_profile=request.native_profile,
        session_id=request.session_id,
        capture_allowed=request.capture_allowed,
        grant_generation=generation,
        policy_generation=config.generation,
        issued_at=now,
        expires_at=now + timedelta(seconds=request.ttl_seconds),
        capability_hash=hash_key(secret),
    )
    session.add(grant)
    session.flush()
    return NativeGrantIssued(
        capability=secret,
        grant_id=grant.grant_id,
        grant_generation=grant.grant_generation,
        policy_generation=grant.policy_generation,
        policy_id=grant.policy_id,
        device_id=grant.device_id,
        native_profile=request.native_profile,
        session_token=grant.session_token,
        session_id=grant.session_id,
        capture_allowed=grant.capture_allowed,
        expires_at=as_utc(grant.expires_at).isoformat(),
    )


def revoke_native_grant(session: Session, grant_id: str, actor_policy_id: str | None, *, now: datetime) -> None:
    policy = session.scalar(select(NativePromptGrant.policy_id).where(NativePromptGrant.grant_id == grant_id))
    if policy is None:
        raise NativeError("invalid_request", 404)
    check_admin_scope(actor_policy_id, policy)
    session.execute(
        update(NativePromptGrant)
        .where(NativePromptGrant.grant_id == grant_id, NativePromptGrant.revoked_at.is_(None))
        .values(revoked_at=now)
    )


def authorize_native(
    session: Session, collector_token_hash: str, capability_hash: str, *, now: datetime
) -> NativePrincipal:
    g = NativePromptGrant
    grant = session.execute(
        select(
            g.device_id,
            g.policy_id,
            g.grant_id,
            g.grant_generation,
            g.policy_generation,
            g.session_token,
            g.native_profile,
            g.capture_allowed,
            g.revoked_at,
            g.expires_at,
            g.session_id,
        ).where(g.capability_hash == capability_hash)
    ).one_or_none()
    if grant is None:
        raise NativeError("unauthorized", 401)
    try:
        collector = authorize_collector(session, collector_token_hash, grant.device_id, now)
    except HTTPException:
        raise NativeError("unauthorized", 401) from None
    if collector.policy_id != grant.policy_id:
        raise NativeError("unauthorized", 403)
    config = read_native_config(session, grant.policy_id)
    if grant.revoked_at is not None or not config.enabled or grant.policy_generation != config.generation:
        raise NativeError("grant_revoked", 403)
    if as_utc(grant.expires_at) <= as_utc(now):
        raise NativeError("grant_expired", 403)
    if grant.capture_allowed and not _native_session_exists(
        session, grant.session_id, grant.device_id, grant.policy_id, grant.session_token, now
    ):
        raise NativeError("grant_revoked", 403)
    return NativePrincipal(
        grant.device_id,
        grant.policy_id,
        collector_token_hash,
        capability_hash,
        grant.grant_id,
        grant.grant_generation,
        grant.policy_generation,
        grant.session_token,
        grant.native_profile,
        grant.capture_allowed,
    )


def upsert_native_observation(
    session: Session, principal: NativePrincipal, metadata: NativeMetadata, *, now: datetime
) -> NativePromptObservation:
    """Caller holds a writer reservation and has reauthorized this principal in it."""
    if metadata.session_token != principal.session_token or metadata.native_profile != principal.profile:
        raise NativeError("unauthorized", 403)
    event = session.scalar(
        select(NativePromptObservation)
        .filter_by(device_id=principal.device_id, occurrence_id=metadata.occurrence_id)
        .execution_options(populate_existing=True)
    )
    if event:
        if event.session_token != principal.session_token or event.policy_id != principal.policy_id:
            raise NativeError("identity_conflict", 409)
        if as_utc(event.expires_at) <= as_utc(now):
            raise NativeError("request_retired", 409)
        return event
    scope = dict(device_id=principal.device_id, agent=metadata.agent, native_session_token=metadata.session_token)
    link = session.scalar(select(AgentSession).filter_by(**scope).execution_options(populate_existing=True))
    if link and link.policy_id != principal.policy_id:
        raise NativeError("identity_conflict", 409)
    if (
        link
        and as_utc(link.received_at) + DETAIL_LIFETIME <= as_utc(now)
        and _retire_session(session, link.session_id, now)
    ):
        link = None
    if link is None:
        link = AgentSession(**scope, policy_id=principal.policy_id, received_at=now)
        session.add(link)
        session.flush()
    event = NativePromptObservation(
        device_id=principal.device_id,
        policy_id=principal.policy_id,
        session_id=link.session_id,
        session_token=metadata.session_token,
        occurrence_id=metadata.occurrence_id,
        native_profile=metadata.native_profile,
        agent=metadata.agent,
        agent_version=metadata.agent_version,
        received_at=now,
        expires_at=now + DETAIL_LIFETIME,
    )
    session.add(event)
    session.flush()
    return event
