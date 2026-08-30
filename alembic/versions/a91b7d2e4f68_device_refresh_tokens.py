"""Per-device refresh credentials

Revision ID: a91b7d2e4f68
Revises: f4c1d8e6b902
Create Date: 2026-08-28

A device offline for longer than an access token's hour could not refresh, and
after approval-by-default re-enrolment needs an administrator. Continuity moves
onto a separate, non-rotating credential with a 30-day life.

No backfill. Existing devices get no refresh token and must re-enrol once --
there is no released client, and inventing credentials for rows that never
agreed to hold one would be worse than the single re-enrolment.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "a91b7d2e4f68"
down_revision = "f4c1d8e6b902"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "device_refresh_tokens",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("token_hash", sa.String(), nullable=False, unique=True),
        sa.Column(
            "device_id",
            sa.String(),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("device_refresh_tokens")
