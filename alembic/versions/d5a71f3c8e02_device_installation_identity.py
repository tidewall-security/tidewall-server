"""device installation identity, registration token scope, token rotation

P0-11: device refresh looked a device up by client-supplied fingerprint and
authorised the refresh on the strength of holding *a* registration token. Any
token holder plus a guessed fingerprint could revoke a victim's session and
obtain an access token bound to their device and policy.

Three schema consequences:

- `devices.installation_id` is the new identity: high-entropy, client-generated
  once, unique. `fingerprint` becomes nullable, non-unique, advisory metadata.
  It was previously both the unique key and the authorisation lookup, which is
  neither identity nor proof — and being unique also let one client deny
  enrolment to another by claiming its fingerprint.
- `registration_tokens.policy_id` gives an enrolling device a scope to inherit.
  There was none, so the middleware set policy_id = None and enrolment
  conferred no binding at all.
- `access_tokens.replaced_by_id` records a rotation, so a refreshed token can
  be expired with a short overlap instead of deleting every token for the
  device — which broke any request already in flight.

Existing device rows cannot be migrated: they have no installation ID and no
way to prove ownership, which is the defect. They are removed, and clients
re-enrol. There are no deployments.

Revision ID: d5a71f3c8e02
Revises: c8f31b0d7a45
Create Date: 2026-08-18

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d5a71f3c8e02"
down_revision: str | Sequence[str] | None = "c8f31b0d7a45"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Access tokens cascade from devices; clear them explicitly so the order is
    # not left to the backend's FK behaviour.
    op.execute("DELETE FROM access_tokens")
    op.execute("DELETE FROM devices")

    op.add_column("registration_tokens", sa.Column("policy_id", sa.String(), nullable=True))
    op.add_column("access_tokens", sa.Column("replaced_by_id", sa.String(), nullable=True))

    # SQLite cannot drop a unique constraint in place, so the table is rebuilt.
    with op.batch_alter_table("devices", schema=None) as batch:
        batch.add_column(sa.Column("installation_id", sa.String(), nullable=False))
        batch.alter_column("fingerprint", existing_type=sa.String(), nullable=True)
        batch.create_unique_constraint("uq_devices_installation_id", ["installation_id"])
        batch.create_index("ix_devices_fingerprint", ["fingerprint"])


def downgrade() -> None:
    op.execute("DELETE FROM access_tokens")
    op.execute("DELETE FROM devices")

    with op.batch_alter_table("devices", schema=None) as batch:
        batch.drop_index("ix_devices_fingerprint")
        batch.drop_constraint("uq_devices_installation_id", type_="unique")
        batch.alter_column("fingerprint", existing_type=sa.String(), nullable=False)
        batch.drop_column("installation_id")

    op.drop_column("access_tokens", "replaced_by_id")
    op.drop_column("registration_tokens", "policy_id")
