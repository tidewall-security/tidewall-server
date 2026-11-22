"""Resolve collector writes solely from persisted access and enrollment state."""

from dataclasses import dataclass
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AccessToken, Device, DeviceTombstone, Policy
from app.utils import as_utc


@dataclass(frozen=True)
class CollectorPrincipal:
    device_id: str
    policy_id: str
    token_hash: str


def authorize_collector(
    session: Session, token_hash: str, expected_device_id: str, now: datetime
) -> CollectorPrincipal:
    # Select scalar values on each adjudication, including at finalization.
    # A Session may already contain ORM instances from middleware or a prior
    # check. Its identity map cannot stand in for the current database rows.
    binding = session.execute(
        select(
            Device.id,
            Device.purpose,
            Device.status,
            Device.collector_approved_at,
            AccessToken.expires_at,
            Policy.id.label("policy_id"),
            DeviceTombstone.device_id.label("tombstone"),
        )
        .select_from(AccessToken)
        .join(Device, Device.id == AccessToken.device_id)
        .outerjoin(Policy, Policy.id == Device.policy_id)
        .outerjoin(DeviceTombstone, DeviceTombstone.device_id == Device.id)
        .where(AccessToken.token_hash == token_hash)
    ).one_or_none()
    if binding is None or as_utc(binding.expires_at) <= as_utc(now) or binding.status != "active" or binding.tombstone:
        raise HTTPException(status_code=401, detail="Collector credential inactive")
    if binding.purpose != "collector_write" or binding.id != expected_device_id or not binding.policy_id:
        raise HTTPException(status_code=403, detail="Collector authority required")
    if binding.collector_approved_at is None:
        raise HTTPException(status_code=401, detail="Collector credential inactive")
    return CollectorPrincipal(binding.id, binding.policy_id, token_hash)
