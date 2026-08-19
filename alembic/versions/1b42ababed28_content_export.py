"""content export

The interlock on export targets, and the durable record of an export attempt
with the evidence around it.

DEPLOYMENT PRECONDITION: a single migrator with writers quiesced. From this
revision onward the server also takes an exclusive lock on the database for its
lifetime, so a rolling replacement must stop the old instance before starting
the new one.

Alembic reports "Will assume non-transactional DDL" on SQLite, so a failure
part-way through leaves whatever already ran and the revision unchanged. Every
step here is therefore IDEMPOTENT: a retry after a partial failure re-runs the
whole upgrade and skips what already exists, rather than failing on a duplicate
column or table and requiring manual repair.

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


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _index(name: str, table: str, columns: list[str]) -> None:
    """Create an index unless it is already there.

    Alembic 1.18's create_index takes no if_not_exists, and this migration has
    to be re-runnable: SQLite DDL here is non-transactional, so a failure
    part-way leaves what already ran and a retry must skip it rather than fail
    on a duplicate.
    """
    inspector = sa.inspect(op.get_bind())
    if name in {i["name"] for i in inspector.get_indexes(table)}:
        return
    op.create_index(name, table, columns)


def upgrade() -> None:
    # --- the interlock -------------------------------------------------------
    #
    # server_default rather than a Python default, so EXISTING rows come out
    # opted out. A default that only applied to new rows would leave every
    # target already configured silently exportable, which is this step
    # inverted.
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("export_targets")}
    to_add = [
        sa.Column("allow_content_export", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("content_export_policy_id", sa.String(), nullable=True),
        sa.Column("content_export_views", sa.JSON(), nullable=False, server_default="[]"),
    ]
    if any(column.name not in existing for column in to_add):
        with op.batch_alter_table("export_targets") as batch:
            for column in to_add:
                if column.name not in existing:
                    batch.add_column(column)

    # --- the attempt ---------------------------------------------------------
    if "content_export_attempts" not in _existing_tables():
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
    _index("ix_content_export_attempts_boot_id", "content_export_attempts", ["boot_id"])
    _index("ix_content_export_attempts_interaction_id", "content_export_attempts", ["interaction_id"])
    _index("ix_content_export_attempts_target_id", "content_export_attempts", ["target_id"])
    _index("ix_content_export_attempts_api_key_id", "content_export_attempts", ["api_key_id"])
    _index("ix_content_export_attempts_created_at", "content_export_attempts", ["created_at"])

    # --- the evidence around it ---------------------------------------------
    #
    # Foreign keys, because attempts are never deleted: omitting them would only
    # permit corrections and notes that point at nothing.
    if "content_export_reconciliations" not in _existing_tables():
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
    _index("ix_content_export_reconciliations_attempt_id", "content_export_reconciliations", ["attempt_id"])

    if "content_export_notes" not in _existing_tables():
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
    _index("ix_content_export_notes_attempt_id", "content_export_notes", ["attempt_id"])


def downgrade() -> None:
    """Reverses the schema. It cannot recall content that was exported."""
    op.drop_table("content_export_notes")
    op.drop_table("content_export_reconciliations")
    op.drop_table("content_export_attempts")
    with op.batch_alter_table("export_targets") as batch:
        batch.drop_column("content_export_views")
        batch.drop_column("content_export_policy_id")
        batch.drop_column("allow_content_export")
