"""Scope approved collectors to a dedicated device purpose."""

import sqlalchemy as sa

from alembic import op

revision = "14e5a91c8b02"
down_revision = "fb6a694ad1fa"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("registration_tokens", "devices", "device_tombstones"):
        # Inline CHECK permits native SQLite ADD / DROP COLUMN. Rebuilding
        # either parent table needlessly risks its descendant credentials.
        op.add_column(
            table,
            sa.Column(
                "purpose",
                sa.String(),
                sa.CheckConstraint("purpose IN ('guard_device', 'collector_write')", name=f"ck_{table}_purpose"),
                server_default="guard_device",
                nullable=False,
            ),
        )
    op.add_column("devices", sa.Column("collector_approved_at", sa.DateTime(), nullable=True))
    op.add_column("device_tombstones", sa.Column("collector_policy_id", sa.String(), nullable=True))


def downgrade() -> None:
    # Older servers would authenticate these credentials as guard devices and
    # permit unscoped recovery. Check before the first schema change.
    if (
        op.get_bind()
        .execute(
            sa.text("""
        SELECT EXISTS(SELECT 1 FROM registration_tokens WHERE purpose='collector_write')
            OR EXISTS(SELECT 1 FROM devices WHERE purpose='collector_write')
            OR EXISTS(SELECT 1 FROM device_tombstones
                      WHERE purpose='collector_write' OR collector_policy_id IS NOT NULL)
    """)
        )
        .scalar()
    ):
        raise RuntimeError("Cannot downgrade while collector identity records exist")
    op.drop_column("device_tombstones", "collector_policy_id")
    op.drop_column("device_tombstones", "purpose")
    op.drop_column("devices", "collector_approved_at")
    op.drop_column("devices", "purpose")
    op.drop_column("registration_tokens", "purpose")
