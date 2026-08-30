"""api_keys.policy_id becomes ON DELETE RESTRICT

It was SET NULL. `PolicyService.delete_policy` counts bound keys and refuses, so
nothing could reach the bad state through the application -- but that made
api_keys the only one of the three things bound to a policy whose guarantee was
a convention rather than a constraint. `devices` and `registration_tokens` are
both RESTRICT, and the comment beside that count says so: "Both foreign keys are
ON DELETE RESTRICT, and that is what holds."

What it holds against: an unbound admin reads and deletes globally, so silently
unbinding a key would promote a policy-scoped administrator to an
organisation-wide one -- a privilege escalation performed by an unrelated
administrative action.

Revision ID: e4b8c2a71f95
Revises: c7d3f1a89e04
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "e4b8c2a71f95"
down_revision: str | Sequence[str] | None = "c7d3f1a89e04"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


#: The existing foreign key is UNNAMED -- SQLite stores it as a bare
#: `FOREIGN KEY(policy_id) REFERENCES policies (id)` -- so `drop_constraint`
#: cannot find it by name. Batch mode accepts a naming convention and applies it
#: to the reflected table, which is how an unnamed constraint is addressed.
_NAMING = {"fk": "fk_%(table_name)s_%(column_0_name)s"}


def upgrade() -> None:
    # SQLite rewrites the table to change a constraint. No data moves: this
    # changes what happens when a policy is deleted, not what any row holds.
    with op.batch_alter_table("api_keys", naming_convention=_NAMING) as batch:
        batch.drop_constraint("fk_api_keys_policy_id", type_="foreignkey")
        batch.create_foreign_key("fk_api_keys_policy_id", "policies", ["policy_id"], ["id"], ondelete="RESTRICT")


def downgrade() -> None:
    with op.batch_alter_table("api_keys", naming_convention=_NAMING) as batch:
        batch.drop_constraint("fk_api_keys_policy_id", type_="foreignkey")
        batch.create_foreign_key("fk_api_keys_policy_id", "policies", ["policy_id"], ["id"], ondelete="SET NULL")
