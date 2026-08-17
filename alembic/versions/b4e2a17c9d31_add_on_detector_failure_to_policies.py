"""add on_detector_failure to policies

Persists the enforcement decision for a detector that cannot run. Without this
the setting lived only on the transient PolicyConfig, so a normally constructed
engine always took the default and every enforcing detector failure was allowed
(P0-2).

Defaults to "report" rather than "block": until the activation preflight exists
and refuses to serve a policy whose required detectors cannot construct,
defaulting to block would turn an absent spaCy model or a gated Hugging Face
model into a service that boots healthy and rejects all traffic.

Revision ID: b4e2a17c9d31
Revises: 82c6e81ffe29
Create Date: 2026-08-16

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b4e2a17c9d31"
down_revision: str | Sequence[str] | None = "82c6e81ffe29"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "policies",
        sa.Column("on_detector_failure", sa.String(), nullable=False, server_default="report"),
    )


def downgrade() -> None:
    op.drop_column("policies", "on_detector_failure")
