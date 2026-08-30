"""safe interaction storage

Every guard evaluation stored the prompt verbatim and served it to any
viewer credential. Four columns on `interactions` carried content:

- `input_messages` — the prompt;
- `output_messages` — the reply;
- `detectors_json` — matched values, raw URLs and offsets;
- `summary` — the matched access-rule name, and detector-derived strings.

`summary` is the one worth naming. It reads like metadata, and it was displayed
*and searched* in the findings UI, so it was both a content channel and the one
least likely to be noticed.

They are dropped rather than nulled. A nullable legacy column is an attractive
sink, keeps stale code compiling, and makes schema inspection advertise a
retention that no longer happens.

Existing rows are deleted. They contain exactly the prompts this finding is
about, and there is no projection that recovers safe evidence from them —
`detectors_json` *is* the unrestricted payload being removed. There are no
deployments.

This revision also creates the tables the later steps need — content, its
access audit, the policy capture settings and the credential grants — inert.
One destructive rebuild of this table is better than two, and creating them
here means the later steps add behaviour rather than schema.

Revision ID: 64c197391e55
Revises: d5a71f3c8e02
Create Date: 2026-08-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "64c197391e55"
down_revision: str | Sequence[str] | None = "d5a71f3c8e02"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Every row holds a prompt. Nothing here is recoverable as safe evidence.
    op.execute("DELETE FROM interactions")

    with op.batch_alter_table("interactions", schema=None) as batch:
        batch.drop_column("input_messages")
        batch.drop_column("output_messages")
        batch.drop_column("detectors_json")
        batch.drop_column("summary")
        batch.add_column(sa.Column("evidence_json", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("evidence_schema_version", sa.Integer(), nullable=False, server_default="1"))
        batch.add_column(sa.Column("content_available", sa.Boolean(), nullable=False, server_default=sa.false()))
        # Reads are scoped by policy, so a null makes the row invisible to every
        # viewer — a silent audit gap. The table is empty at this point, so the
        # NOT NULL costs nothing.
        batch.alter_column("policy_id", existing_type=sa.String(), nullable=False)

    op.create_index("ix_interactions_policy_timestamp", "interactions", ["policy_id", "timestamp"])
    op.create_index("ix_interactions_policy_status_timestamp", "interactions", ["policy_id", "status", "timestamp"])
    op.create_index("ix_interactions_device_id", "interactions", ["device_id"])

    # Capture settings. Off by default: a fresh install retains no prompts
    # until an operator turns it on.
    with op.batch_alter_table("policies", schema=None) as batch:
        batch.add_column(sa.Column("raw_content_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("raw_content_retention_days", sa.Integer(), nullable=True))

    # Content grants, orthogonal to the role rather than implied by it.
    with op.batch_alter_table("api_keys", schema=None) as batch:
        batch.add_column(sa.Column("grants", sa.JSON(), nullable=True))

    op.create_table(
        "interaction_contents",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("interaction_id", sa.Integer(), nullable=False, unique=True),
        sa.Column("input_json", sa.JSON(), nullable=True),
        sa.Column("output_json", sa.JSON(), nullable=True),
        sa.Column("matches_json", sa.JSON(), nullable=True),
        sa.Column("byte_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("captured_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        # Deleting the event deletes its content; the reverse is not true.
        sa.ForeignKeyConstraint(["interaction_id"], ["interactions.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_interaction_contents_captured_at", "interaction_contents", ["captured_at"])
    op.create_index("ix_interaction_contents_expires_at", "interaction_contents", ["expires_at"])

    op.create_table(
        "content_access_audit",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        # Deliberately not a foreign key: the audit must outlive the row it
        # describes, or deleting content would erase the record of who read it.
        sa.Column("interaction_id", sa.Integer(), nullable=False),
        sa.Column("api_key_id", sa.String(), nullable=True),
        sa.Column("tier", sa.String(), nullable=False),
        sa.Column("policy_id", sa.String(), nullable=True),
        sa.Column("accessed_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_content_access_audit_interaction_id", "content_access_audit", ["interaction_id"])
    op.create_index("ix_content_access_audit_api_key_id", "content_access_audit", ["api_key_id"])
    op.create_index("ix_content_access_audit_accessed_at", "content_access_audit", ["accessed_at"])


def downgrade() -> None:
    op.execute("DELETE FROM interactions")

    op.drop_table("content_access_audit")
    op.drop_table("interaction_contents")

    with op.batch_alter_table("api_keys", schema=None) as batch:
        batch.drop_column("grants")

    with op.batch_alter_table("policies", schema=None) as batch:
        batch.drop_column("raw_content_retention_days")
        batch.drop_column("raw_content_enabled")

    op.drop_index("ix_interactions_device_id", table_name="interactions")
    op.drop_index("ix_interactions_policy_status_timestamp", table_name="interactions")
    op.drop_index("ix_interactions_policy_timestamp", table_name="interactions")

    with op.batch_alter_table("interactions", schema=None) as batch:
        batch.alter_column("policy_id", existing_type=sa.String(), nullable=True)
        batch.drop_column("content_available")
        batch.drop_column("evidence_schema_version")
        batch.drop_column("evidence_json")
        batch.add_column(sa.Column("summary", sa.Text(), nullable=True))
        batch.add_column(sa.Column("detectors_json", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("output_messages", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("input_messages", sa.JSON(), nullable=True))
