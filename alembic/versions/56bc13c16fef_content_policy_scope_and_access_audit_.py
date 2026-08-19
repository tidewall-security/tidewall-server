"""content policy scope and access audit fields

Adds the duplicated policy on captured content, and the fields the content
access audit needs to be useful to an investigator.

DEPLOYMENT PRECONDITION: a single migrator with writers quiesced. This
application auto-migrates at startup and several serving processes can race a
SQLite batch rebuild; batch mode is transactional but that does not make it
online.

Revision ID: 56bc13c16fef
Revises: 64c197391e55
Create Date: 2026-08-19
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "56bc13c16fef"
down_revision: str | Sequence[str] | None = "64c197391e55"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- interaction_contents.policy_id -------------------------------------
    #
    # Nullable first: SQLite cannot add a populated NOT NULL column without a
    # default, and inventing a default for a policy id would be worse than
    # failing.
    op.add_column("interaction_contents", sa.Column("policy_id", sa.String(), nullable=True))

    op.execute(
        """
        UPDATE interaction_contents
           SET policy_id = (SELECT i.policy_id
                              FROM interactions i
                             WHERE i.id = interaction_contents.interaction_id)
        """
    )

    # Step 4 made interactions.policy_id NOT NULL, so a conforming database
    # cannot produce a null here. This catches the databases that are not
    # conforming: one edited by hand, or written over a connection with foreign
    # keys off. Aborting leaves the old revision and the old table intact.
    conn = op.get_bind()
    unresolved = conn.execute(sa.text("SELECT COUNT(*) FROM interaction_contents WHERE policy_id IS NULL")).scalar()
    if unresolved:
        raise RuntimeError(
            f"{unresolved} interaction_contents row(s) have no resolvable policy: "
            "their parent interaction is missing or has no policy. Refusing to "
            "invent one. Investigate before migrating."
        )

    with op.batch_alter_table("interaction_contents") as batch:
        batch.alter_column("policy_id", existing_type=sa.String(), nullable=False)
    op.create_index("ix_interaction_contents_policy_id", "interaction_contents", ["policy_id"])

    # --- content_access_audit ----------------------------------------------
    #
    # All nullable so any row written before this step survives. tier already
    # carries matches|full and is kept as the view field; a second column
    # meaning the same thing would only create a way to write one and not the
    # other.
    for column in (
        sa.Column("actor_role", sa.String(), nullable=True),
        sa.Column("grant_used", sa.String(), nullable=True),
        sa.Column("outcome", sa.String(), nullable=True),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("attempt_id", sa.String(), nullable=True),
        sa.Column("source_ip", sa.String(), nullable=True),
    ):
        op.add_column("content_access_audit", column)
    op.create_index("ix_content_access_audit_attempt_id", "content_access_audit", ["attempt_id"])


def downgrade() -> None:
    """Reverses the schema. It cannot restore purged content and does not try."""
    op.drop_index("ix_content_access_audit_attempt_id", table_name="content_access_audit")
    for name in ("source_ip", "attempt_id", "reason", "outcome", "grant_used", "actor_role"):
        op.drop_column("content_access_audit", name)

    op.drop_index("ix_interaction_contents_policy_id", table_name="interaction_contents")
    op.drop_column("interaction_contents", "policy_id")
