"""Bound pending state: a per-key counter of unapproved devices

Revision ID: d5e91a3c7b40
Revises: b83f2c5a91d7
Create Date: 2026-08-28

Approval-by-default turned a leaked key from "a working fleet" into "unbounded
pending rows". The counter is maintained by conditional DML in the transaction
that inserts the device, because counting rows and then inserting is
check-then-act and SQLite serialises the writes but not the reads before them.

Backfilled from the rows that exist, so a deployment mid-flight does not start
from zero and admit another full quota.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "d5e91a3c7b40"
down_revision = "b83f2c5a91d7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "registration_tokens",
        sa.Column("pending_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.execute(
        "UPDATE registration_tokens SET pending_count = ("
        "  SELECT COUNT(*) FROM devices"
        "  WHERE devices.reg_token_id = registration_tokens.id AND devices.status = 'pending'"
        ")"
    )


def downgrade() -> None:
    op.drop_column("registration_tokens", "pending_count")
