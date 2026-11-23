"""Purple teaming quick tests: assessments get a kind ("assessment" or "quick")

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-19 09:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("pt_assessments") as batch:
        batch.add_column(
            sa.Column("kind", sa.String(length=16), nullable=False, server_default="assessment")
        )


def downgrade() -> None:
    # the quick tests container stays and shows up as an ordinary assessment again
    with op.batch_alter_table("pt_assessments") as batch:
        batch.drop_column("kind")
