"""content export

The interlock on export targets, and the durable record of an export attempt
with the evidence around it.

DEPLOYMENT PRECONDITION: a single migrator with writers quiesced. From this
revision onward the server also takes an exclusive lock on the database for its
lifetime, so a rolling replacement must stop the old instance before starting
the new one.

Revision ID: 1b42ababed28
Revises: 56bc13c16fef
Create Date: 2026-08-19
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "1b42ababed28"
down_revision: str | Sequence[str] | None = "56bc13c16fef"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- the interlock -------------------------------------------------------
    #
    # server_default rather than a Python default, so EXISTING rows come out
    # opted out. A default that only applied to new rows would leave every
    # target already configured silently exportable, which is this step
    # inverted.
    with op.batch_alter_table("export_targets") as batch:
        batch.add_column(sa.Column("allow_content_export", sa.Boolean(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("content_export_policy_id", sa.String(), nullable=True))
        batch.add_column(sa.Column("content_export_views", sa.JSON(), nullable=False, server_default="[]"))

    # --- the attempt ---------------------------------------------------------
    op.create_table(
        "content_export_attempts",
        sa.Column("attempt_id", sa.String(), primary_key=True),
        sa.Column("interaction_id", sa.Integer(), nullable=False),
        sa.Column("policy_id", sa.String(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("api_key_id", sa.String(), nullable=True),
        sa.Column("actor_role", sa.String(), nullable=True),
        sa.Column("view", sa.String(), nullable=False),
        sa.Column("grant_used", sa.String(), nullable=True),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("transport_status", sa.Integer(), nullable=True),
        sa.Column("payload_bytes", sa.Integer(), nullable=False),
        sa.Column("idempotency_key_digest", sa.String(), nullable=True),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("destination_host", sa.String(), nullable=False),
        sa.Column("destination_port", sa.Integer(), nullable=False),
        sa.Column("destination_addrs", sa.JSON(), nullable=False),
        sa.Column("destination_addr", sa.String(), nullable=True),
        sa.Column("target_config_digest", sa.String(), nullable=False),
        sa.Column("boot_id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("settled_at", sa.DateTime(), nullable=True),
        # The reservation. A check-then-insert lets two concurrent requests with
        # the same key both pass the check and disclose twice.
        sa.UniqueConstraint("api_key_id", "idempotency_key_digest", name="uq_content_export_idempotency"),
        sa.CheckConstraint(
            "state IN ('pending','succeeded','failed','indeterminate','abandoned_indeterminate')",
            name="ck_content_export_state",
        ),
        # Constraints rather than conventions: pending implies nothing settled,
        # terminal implies something did.
        sa.CheckConstraint(
            "(state = 'pending' AND settled_at IS NULL AND transport_status IS NULL) "
            "OR (state != 'pending' AND settled_at IS NOT NULL)",
            name="ck_content_export_settlement",
        ),
        sa.CheckConstraint(
            "transport_status IS NULL OR (transport_status >= 100 AND transport_status <= 599)",
            name="ck_content_export_status_range",
        ),
    )
    op.create_index("ix_content_export_attempts_boot_id", "content_export_attempts", ["boot_id"])
    op.create_index("ix_content_export_attempts_interaction_id", "content_export_attempts", ["interaction_id"])
    op.create_index("ix_content_export_attempts_target_id", "content_export_attempts", ["target_id"])
    op.create_index("ix_content_export_attempts_api_key_id", "content_export_attempts", ["api_key_id"])
    op.create_index("ix_content_export_attempts_created_at", "content_export_attempts", ["created_at"])

    # --- the evidence around it ---------------------------------------------
    #
    # Foreign keys, because attempts are never deleted: omitting them would only
    # permit corrections and notes that point at nothing.
    op.create_table(
        "content_export_reconciliations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("attempt_id", sa.String(), sa.ForeignKey("content_export_attempts.attempt_id"), nullable=False),
        sa.Column("from_state", sa.String(), nullable=False),
        sa.Column("to_state", sa.String(), nullable=False),
        sa.Column("evidence", sa.String(), nullable=False),
        sa.Column("reconciled_by", sa.String(), nullable=True),
        sa.Column("reconciled_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "to_state IN ('succeeded','failed','indeterminate')",
            name="ck_content_export_reconciliation_to",
        ),
    )
    op.create_index("ix_content_export_reconciliations_attempt_id", "content_export_reconciliations", ["attempt_id"])

    op.create_table(
        "content_export_notes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("attempt_id", sa.String(), sa.ForeignKey("content_export_attempts.attempt_id"), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("detail", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "kind IN ('settlement_lost','body_read_failed','settlement_commit_failed','cleanup_failed')",
            name="ck_content_export_note_kind",
        ),
    )
    op.create_index("ix_content_export_notes_attempt_id", "content_export_notes", ["attempt_id"])


def downgrade() -> None:
    """Reverses the schema. It cannot recall content that was exported."""
    op.drop_table("content_export_notes")
    op.drop_table("content_export_reconciliations")
    op.drop_table("content_export_attempts")
    with op.batch_alter_table("export_targets") as batch:
        batch.drop_column("content_export_views")
        batch.drop_column("content_export_policy_id")
        batch.drop_column("allow_content_export")
