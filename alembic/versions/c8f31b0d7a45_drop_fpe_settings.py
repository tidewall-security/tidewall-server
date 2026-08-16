"""drop fpe_settings

Format-preserving encryption is removed. The investigation is recorded in
internal reviews 2026-08-15-fpe-options-spike.md and the design-around journal;
in short: FF3-1 was withdrawn from NIST SP 800-38G Rev 1, the `ff3` package
self-describes as educational, FF1 is patent-encumbered until 2029, FEA is
broken, and no design-around clears both the patents and the cryptanalysis.

This drops the table that held a single global AES key as raw bytes in the same
database as the ciphertext it protected. The key is destroyed with it, which is
intended: nothing in the shipping code ever produced FPE ciphertext, because
the PII detector never constructed a Redactor with an FPE service, so there is
nothing to decrypt.

Revision ID: c8f31b0d7a45
Revises: b4e2a17c9d31
Create Date: 2026-08-16

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c8f31b0d7a45"
down_revision: str | Sequence[str] | None = "b4e2a17c9d31"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_table("fpe_settings")


def downgrade() -> None:
    # Recreates the shape only. The key is not restored — it was destroyed on
    # upgrade, deliberately, and re-adding an empty table is the honest inverse.
    op.create_table(
        "fpe_settings",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("key", sa.LargeBinary(), nullable=False),
        sa.Column("tweak", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
