"""content policy scope and access audit fields

Adds the duplicated policy on captured content, and the fields the content
access audit needs to be useful to an investigator.

DEPLOYMENT PRECONDITION: a single migrator with writers quiesced. This
application auto-migrates at startup and several serving processes can race a
SQLite batch rebuild.

Alembic runs this environment with non-transactional DDL on SQLite, so raising
part-way does NOT roll the schema back. Everything that can refuse is therefore
checked before the first DDL statement, and the one check that cannot be
(after the backfill) undoes its own column before raising -- so a refusal
always leaves the previous schema, at the previous revision, and retryable.

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
    conn = op.get_bind()

    # --- refuse before touching anything ------------------------------------
    #
    # Alembic reports "non-transactional DDL" on SQLite, so a raise part-way
    # through leaves whatever DDL already ran. An earlier version of this
    # migration added the column first and then aborted, leaving a database
    # that was neither the old schema nor the new one -- and whose retry failed
    # at ADD COLUMN instead of re-reporting the real problem.
    #
    # Step 4 made interactions.policy_id NOT NULL, so a conforming database
    # cannot fail this. It catches the ones that are not conforming: edited by
    # hand, or written over a connection with foreign keys off.
    orphans = conn.execute(
        sa.text(
            """
            SELECT COUNT(*)
              FROM interaction_contents c
              LEFT JOIN interactions i ON i.id = c.interaction_id
             WHERE i.id IS NULL OR i.policy_id IS NULL OR i.policy_id = ''
            """
        )
    ).scalar()
    if orphans:
        raise RuntimeError(
            f"{orphans} interaction_contents row(s) have no resolvable policy: "
            "their parent interaction is missing or has no policy. Refusing to "
            "invent one. Investigate before migrating; nothing has been changed."
        )

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

    # Belt and braces: the pre-check above should make this unreachable. If it
    # is ever reached, undo the column before raising, so the refusal still
    # leaves the previous schema and a retry re-reports the real problem rather
    # than failing at ADD COLUMN.
    unresolved = conn.execute(sa.text("SELECT COUNT(*) FROM interaction_contents WHERE policy_id IS NULL")).scalar()
    if unresolved:
        op.drop_column("interaction_contents", "policy_id")
        raise RuntimeError(
            f"{unresolved} interaction_contents row(s) were not backfilled. "
            "Refusing to invent a policy. The schema has been left unchanged."
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
