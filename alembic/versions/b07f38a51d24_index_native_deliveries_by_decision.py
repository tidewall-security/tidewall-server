"""Index delivery summaries and cascading decision deletions."""

from alembic import op

revision = "b07f38a51d24"
down_revision = "9a42c7d3e601"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_native_prompt_deliveries_decision_id", "native_prompt_deliveries", ["decision_id"])


def downgrade() -> None:
    op.drop_index("ix_native_prompt_deliveries_decision_id", table_name="native_prompt_deliveries")
