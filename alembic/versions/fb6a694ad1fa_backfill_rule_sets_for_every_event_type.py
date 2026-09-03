"""backfill rule sets for every event type

Revision ID: fb6a694ad1fa
Revises: e4b8c2a71f95
Create Date: 2026-09-02 22:29:51.328020

"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "fb6a694ad1fa"
down_revision: str | Sequence[str] | None = "e4b8c2a71f95"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# The three event types the schema has always accepted and that no creation
# path ever produced a rule set for. Named literally rather than derived from
# EVENT_TYPES: a migration describes the database at a point in time, and must
# not change meaning when application constants later do.
_BACKFILLED = ("tool_input", "tool_output", "tool_listing")


def upgrade() -> None:
    """Give every existing policy a rule set for each missing event type.

    Copies `detectors` from that policy's `input` row and nothing else.

    `report_only` and access rules are deliberately NOT copied. The guard reads
    the requested event type's own row for both, and finds nothing today -- so
    inheriting them would newly apply input's access rules to tool events, which
    can block before any detector runs, and an input-row report_only override
    would change tool-event dispositions. Copying the whole row would look like
    the conservative choice and would not be.

    Idempotent: rows that already exist are left alone, so a re-run adds
    nothing.
    """
    conn = op.get_bind()

    policies = conn.execute(sa.text("SELECT id FROM policies")).fetchall()
    for (policy_id,) in policies:
        detectors = conn.execute(
            sa.text("SELECT detectors FROM rule_sets " "WHERE policy_id = :p AND event_type = 'input'"),
            {"p": policy_id},
        ).scalar()
        # A policy with no input row is malformed rather than impossible; give
        # it empty detectors instead of failing the migration for the estate.
        if detectors is None:
            detectors = "{}"

        existing = {
            row[0]
            for row in conn.execute(
                sa.text("SELECT event_type FROM rule_sets WHERE policy_id = :p"),
                {"p": policy_id},
            ).fetchall()
        }

        for event_type in _BACKFILLED:
            if event_type in existing:
                continue
            conn.execute(
                sa.text(
                    "INSERT INTO rule_sets (id, policy_id, event_type, detectors, report_only) "
                    "VALUES (:id, :p, :e, :d, NULL)"
                ),
                {"id": str(uuid.uuid4()), "p": policy_id, "e": event_type, "d": detectors},
            )


def downgrade() -> None:
    """Remove the backfilled rule sets.

    Access rules attached to them would be removed by cascade. The backfill
    creates none, so this is safe for rows this migration made -- but an
    operator who has since attached access rules to a tool rule set would lose
    them, which is why that is said here rather than discovered.
    """
    conn = op.get_bind()
    conn.execute(sa.text("DELETE FROM rule_sets WHERE event_type IN ('tool_input', 'tool_output', 'tool_listing')"))
