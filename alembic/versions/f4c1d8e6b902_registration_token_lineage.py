"""Enrolment lineage that survives key deletion, and soft revocation

Revision ID: f4c1d8e6b902
Revises: e2f8a4b71c53
Create Date: 2026-08-27

`devices.reg_token_id` is ondelete=SET NULL. Deleting a registration token
therefore erases the record of which devices it created -- at exactly the moment
that record is needed, because deleting the key is the first thing an
administrator does on discovering it has leaked.

`reg_token_prefix` snapshots the answer onto the device row, where no foreign
key can null it. The backfill reads the existing relationships before anything
can drop them.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "f4c1d8e6b902"
down_revision = "e2f8a4b71c53"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("registration_tokens", sa.Column("revoked_at", sa.DateTime(), nullable=True))
    op.add_column("devices", sa.Column("reg_token_prefix", sa.String(), nullable=True))
    op.create_index("ix_devices_reg_token_prefix", "devices", ["reg_token_prefix"])

    # Backfill from the live relationship. Devices whose token was already
    # deleted have reg_token_id NULL and stay unattributable: that history is
    # gone and this migration cannot invent it.
    op.execute(
        "UPDATE devices SET reg_token_prefix = ("
        "  SELECT token_prefix FROM registration_tokens"
        "  WHERE registration_tokens.id = devices.reg_token_id"
        ") WHERE reg_token_id IS NOT NULL"
    )


def downgrade() -> None:
    op.drop_index("ix_devices_reg_token_prefix", table_name="devices")
    op.drop_column("devices", "reg_token_prefix")
    op.drop_column("registration_tokens", "revoked_at")
