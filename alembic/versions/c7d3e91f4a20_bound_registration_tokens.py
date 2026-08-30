"""Bound registration tokens: mandatory expiry, use ceiling

Revision ID: c7d3e91f4a20
Revises: 1b42ababed28
Create Date: 2026-08-27

An enrolment key with no deadline is a permanent capability to create devices.
Expiry becomes mandatory, and a key may carry a ceiling on how many devices it
can enrol.

Backfill runs BEFORE the NOT NULL is applied. Existing unbounded keys are given
a deadline rather than deleted -- they may be in live use by a fleet -- and 90
days from migration matches the ceiling the service now enforces on creation.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c7d3e91f4a20"
down_revision = "1b42ababed28"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("registration_tokens", sa.Column("max_uses", sa.Integer(), nullable=True))
    op.add_column(
        "registration_tokens",
        sa.Column("uses", sa.Integer(), nullable=False, server_default="0"),
    )

    # Backfill first: tightening to NOT NULL fails on any existing NULL row.
    op.execute("UPDATE registration_tokens SET expires_at = datetime('now', '+90 days') WHERE expires_at IS NULL")

    # batch_alter_table because SQLite cannot ALTER COLUMN in place; Alembic
    # rebuilds the table and copies the rows.
    with op.batch_alter_table("registration_tokens") as batch:
        batch.alter_column("expires_at", existing_type=sa.DateTime(), nullable=False)


def downgrade() -> None:
    with op.batch_alter_table("registration_tokens") as batch:
        batch.alter_column("expires_at", existing_type=sa.DateTime(), nullable=True)
    op.drop_column("registration_tokens", "uses")
    op.drop_column("registration_tokens", "max_uses")
