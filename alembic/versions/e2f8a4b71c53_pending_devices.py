"""Approval by default: pending devices and a confirmation code

Revision ID: e2f8a4b71c53
Revises: c7d3e91f4a20
Create Date: 2026-08-27

Enrolment yields a pending device unless its registration token is explicitly
pre-authorized. The device receives credentials and no api role until an
administrator confirms it against a server-generated code.

Existing rows take the safe direction deliberately:

- Devices are already `active` and keep that status with a NULL confirmation
  code. They are approved; nothing about them changed.
- Registration tokens get `pre_authorized = 0`, so previously-issued keys stop
  minting active devices. That is the point of the change, and it means any
  fleet key in flight needs re-issuing with the flag set.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "e2f8a4b71c53"
down_revision = "c7d3e91f4a20"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "registration_tokens",
        sa.Column("pre_authorized", sa.Boolean(), nullable=False, server_default="0"),
    )
    op.add_column("devices", sa.Column("confirmation_code", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("devices", "confirmation_code")
    op.drop_column("registration_tokens", "pre_authorized")
