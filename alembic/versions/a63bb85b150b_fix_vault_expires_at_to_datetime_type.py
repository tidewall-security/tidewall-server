"""fix vault expires_at to datetime type

Revision ID: a63bb85b150b
Revises: 96678131acc3
Create Date: 2026-03-27 21:56:59.137139

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a63bb85b150b'
down_revision: str | Sequence[str] | None = '96678131acc3'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Use batch mode for SQLite compatibility (ALTER TABLE not fully supported)
    with op.batch_alter_table('rule_sets') as batch_op:
        batch_op.create_unique_constraint('uq_rule_sets_policy_event', ['policy_id', 'event_type'])

    with op.batch_alter_table('vaults') as batch_op:
        batch_op.alter_column('expires_at',
                              existing_type=sa.VARCHAR(),
                              type_=sa.DateTime(),
                              existing_nullable=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('vaults') as batch_op:
        batch_op.alter_column('expires_at',
                              existing_type=sa.DateTime(),
                              type_=sa.VARCHAR(),
                              existing_nullable=False)

    with op.batch_alter_table('rule_sets') as batch_op:
        batch_op.drop_constraint('uq_rule_sets_policy_event', type_='unique')
