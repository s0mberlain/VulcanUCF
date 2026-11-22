"""Description (Markdown) on tests and library templates (PROJ-3)

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-22 18:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    for table in ("test_cases", "test_templates"):
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column("description", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    for table in ("test_cases", "test_templates"):
        with op.batch_alter_table(table) as batch:
            batch.drop_column("description")
