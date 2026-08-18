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


# The original tables were created with unnamed UNIQUE constraints. Batch mode
# reflects them, and one it cannot name is one it cannot drop — it is silently
# carried into the rebuilt table instead. Supplying the convention lets the
# reflected constraint be addressed as `uq_devices_fingerprint`.
_NAMING = {"uq": "uq_%(table_name)s_%(column_0_name)s"}


def _fingerprint_unique_name() -> str | None:
    """The real name of the UNIQUE constraint on devices.fingerprint.

    Only SQLite leaves it unnamed for the convention above to supply; other
    backends generate their own (PostgreSQL uses `devices_fingerprint_key`),
    and reflection returns that generated name rather than ours. Hard-coding
    `uq_devices_fingerprint` would therefore fail everywhere except the backend
    it was tested on, so ask the database what it actually called it.
    """
    inspector = sa.inspect(op.get_bind())
    for constraint in inspector.get_unique_constraints("devices"):
        if constraint["column_names"] == ["fingerprint"]:
            return constraint["name"] or "uq_devices_fingerprint"
    return None


def upgrade() -> None:
    # Access tokens cascade from devices; clear them explicitly so the order is
    # not left to the backend's FK behaviour.
    op.execute("DELETE FROM access_tokens")
    op.execute("DELETE FROM devices")

    op.add_column("access_tokens", sa.Column("replaced_by_id", sa.String(), nullable=True))

    # Batch mode so the foreign key is really created: SQLite cannot add one to
    # an existing table in place, and adding the column alone would leave a
    # migrated database without the referential integrity a freshly created one
    # gets from the ORM metadata.
    with op.batch_alter_table("registration_tokens", schema=None) as batch:
        batch.add_column(sa.Column("policy_id", sa.String(), nullable=True))
        batch.create_foreign_key(
            "fk_registration_tokens_policy_id", "policies", ["policy_id"], ["id"], ondelete="SET NULL"
        )

    # Discover the name before batch mode rebuilds the table under us.
    fingerprint_unique = _fingerprint_unique_name()

    # SQLite cannot drop a unique constraint in place, so the table is rebuilt.
    with op.batch_alter_table("devices", schema=None, naming_convention=_NAMING) as batch:
        batch.add_column(sa.Column("installation_id", sa.String(), nullable=False))
        batch.alter_column("fingerprint", existing_type=sa.String(), nullable=True)
        # Fingerprint stops being unique, not just stops being identity. Leaving
        # the constraint would keep the denial-of-enrolment half of P0-11: two
        # installations reporting the same fingerprint — explicitly allowed now
        # — could not both enrol, and the loser would get an IntegrityError.
        if fingerprint_unique:
            batch.drop_constraint(fingerprint_unique, type_="unique")
        batch.create_unique_constraint("uq_devices_installation_id", ["installation_id"])
        batch.create_index("ix_devices_fingerprint", ["fingerprint"])


def downgrade() -> None:
    op.execute("DELETE FROM access_tokens")
    op.execute("DELETE FROM devices")

    with op.batch_alter_table("devices", schema=None, naming_convention=_NAMING) as batch:
        batch.drop_index("ix_devices_fingerprint")
        batch.drop_constraint("uq_devices_installation_id", type_="unique")
        batch.create_unique_constraint("uq_devices_fingerprint", ["fingerprint"])
        batch.alter_column("fingerprint", existing_type=sa.String(), nullable=False)
        batch.drop_column("installation_id")

    op.drop_column("access_tokens", "replaced_by_id")

    with op.batch_alter_table("registration_tokens", schema=None) as batch:
        batch.drop_constraint("fk_registration_tokens_policy_id", type_="foreignkey")
        batch.drop_column("policy_id")
