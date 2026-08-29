"""Vault ownership: a vault belongs to the policy that created it

Existing rows are deleted rather than migrated. No owner was ever recorded and
none can be recovered, they are at most an hour old, and they hold the
placeholder-to-original mapping -- the PII itself. A row whose owner cannot be
established must not stay reversible by everyone.

Every worker must be restarted alongside this migration. ``VaultManager``'s
cache is process-local and a hit returns a decrypted vault without consulting
the row, so deleting rows does not revoke what a running process already holds.

Revision ID: c7d3f1a89e04
Revises: d5e91a3c7b40
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c7d3f1a89e04"
down_revision: str | Sequence[str] | None = "d5e91a3c7b40"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("DELETE FROM vaults")
    # SQLite cannot add a NOT NULL column or a constraint in place.
    with op.batch_alter_table("vaults") as batch:
        batch.add_column(sa.Column("policy_id", sa.String(), nullable=False))
        batch.add_column(sa.Column("created_by_key_id", sa.String(), nullable=True))
        batch.create_foreign_key(
            "fk_vaults_policy_id", "policies", ["policy_id"], ["id"], ondelete="CASCADE"
        )
        batch.create_index("ix_vaults_policy_id", ["policy_id"])


def downgrade() -> None:
    # They cannot survive losing their owner: without it every credential could
    # reverse every one of them again.
    op.execute("DELETE FROM vaults")
    with op.batch_alter_table("vaults") as batch:
        batch.drop_index("ix_vaults_policy_id")
        batch.drop_constraint("fk_vaults_policy_id", type_="foreignkey")
        batch.drop_column("created_by_key_id")
        batch.drop_column("policy_id")
