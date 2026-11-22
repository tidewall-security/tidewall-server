"""Store scoped metadata observations, committed outcomes and collector health."""

import sqlalchemy as sa

from alembic import op

revision = "c81b0704d921"
down_revision = "14e5a91c8b02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "agent_sessions",
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("policy_id", sa.String(), nullable=False),
        sa.Column("agent", sa.String(), nullable=False),
        sa.Column("native_session_token", sa.String(length=64), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("session_id"),
        sa.UniqueConstraint("device_id", "agent", "native_session_token"),
        sa.UniqueConstraint("session_id", "device_id", "policy_id", "agent"),
    )
    op.create_index(
        "ix_agent_sessions_policy_time", "agent_sessions", ["policy_id", "received_at", "session_id"], unique=False
    )
    op.create_table(
        "collector_progress",
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("policy_id", sa.String(), nullable=False),
        sa.Column("high_water", sa.Integer(), nullable=False),
        sa.Column("heartbeat_revision", sa.Integer(), nullable=False),
        sa.Column("heartbeat_digest", sa.String(length=64), nullable=True),
        sa.Column("totals", sa.JSON(), nullable=False),
        sa.Column("heartbeat_json", sa.Text(), nullable=True),
        sa.Column("heartbeat_received_at", sa.DateTime(), nullable=True),
        sa.Column("heartbeat_expires_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("heartbeat_revision BETWEEN 0 AND 9007199254740991", name="ck_collector_revision"),
        sa.CheckConstraint("high_water BETWEEN 0 AND 9007199254740991", name="ck_collector_high_water"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("device_id"),
    )
    op.create_index(
        "ix_collector_health_policy_time",
        "collector_progress",
        ["policy_id", "heartbeat_received_at", "device_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_collector_progress_heartbeat_expires_at"), "collector_progress", ["heartbeat_expires_at"], unique=False
    )
    op.create_table(
        "agent_observations",
        sa.Column("event_id", sa.String(), nullable=False),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("policy_id", sa.String(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("agent", sa.String(), nullable=False),
        sa.Column("channel", sa.String(), nullable=False),
        sa.Column("source_key", sa.String(length=64), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("observation_json", sa.Text(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["session_id", "device_id", "policy_id", "agent"],
            [
                "agent_sessions.session_id",
                "agent_sessions.device_id",
                "agent_sessions.policy_id",
                "agent_sessions.agent",
            ],
        ),
        sa.PrimaryKeyConstraint("event_id"),
        sa.UniqueConstraint("device_id", "agent", "channel", "source_key"),
        sa.UniqueConstraint("event_id", "device_id"),
    )
    op.create_index(op.f("ix_agent_observations_expires_at"), "agent_observations", ["expires_at"], unique=False)
    op.create_index(
        "ix_agent_observations_policy_time",
        "agent_observations",
        ["policy_id", "received_at", "event_id"],
        unique=False,
    )
    op.create_index(
        "ix_agent_observations_session_time",
        "agent_observations",
        ["session_id", "received_at", "event_id"],
        unique=False,
    )
    op.create_table(
        "collector_outcomes",
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("event_id", sa.String(), nullable=True),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "(outcome IN ('accepted','duplicate') AND event_id IS NOT NULL AND reason IS NULL) OR "
            "(outcome = 'rejected' AND event_id IS NULL AND reason IS NOT NULL "
            "AND reason IN ('identity_conflict','retired_ordinal'))",
            name="ck_collector_disposition",
        ),
        sa.CheckConstraint("ordinal BETWEEN 1 AND 9007199254740991", name="ck_collector_ordinal"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["event_id", "device_id"],
            ["agent_observations.event_id", "agent_observations.device_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("device_id", "ordinal", "digest"),
    )
    op.create_index("ix_collector_outcomes_event", "collector_outcomes", ["event_id", "device_id"], unique=False)
    op.create_index(op.f("ix_collector_outcomes_expires_at"), "collector_outcomes", ["expires_at"], unique=False)
    op.create_index(
        "uq_collector_successful_ordinal",
        "collector_outcomes",
        ["device_id", "ordinal"],
        unique=True,
        sqlite_where=sa.text("event_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_table("collector_outcomes")
    op.drop_table("agent_observations")
    op.drop_table("collector_progress")
    op.drop_table("agent_sessions")
