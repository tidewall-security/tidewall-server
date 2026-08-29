"""Durable evidence that a device was revoked

Revision ID: b83f2c5a91d7
Revises: a91b7d2e4f68
Create Date: 2026-08-28

Revocation deletes a device's credentials, so a client that returns later
presents something unknown and is told to re-enrol -- taking the recovery path
and undoing its own revocation. The tombstone is what makes "stop permanently"
outlive the credentials it was enforced through.

No foreign key to devices: the row must survive that device's deletion, which
is the case it exists for.

No backfill. Devices revoked before this migration have no tombstone and can
re-enrol; there is no record of them to reconstruct one from.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "b83f2c5a91d7"
down_revision = "a91b7d2e4f68"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_tombstones",
        sa.Column("device_id", sa.String(), primary_key=True),
        sa.Column("installation_id", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("recovery_secret_hash", sa.String(), nullable=True),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_device_tombstones_installation_id", "device_tombstones", ["installation_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_device_tombstones_installation_id", table_name="device_tombstones")
    op.drop_table("device_tombstones")
