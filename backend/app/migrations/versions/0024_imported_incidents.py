"""Imported incidents from SIEM case exports (output metrics CSV import)

Revision ID: 0024
Revises: 0023
Create Date: 2026-11-24 10:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "imported_incidents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.String(64), nullable=False),
        sa.Column(
            "l3_id",
            sa.Integer(),
            sa.ForeignKey("l3_use_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("period", sa.Date(), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("imported_by", sa.String(64), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("incident_id", "l3_id"),
    )
    op.create_index("ix_imported_incidents_incident_id", "imported_incidents", ["incident_id"])
    op.create_index("ix_imported_incidents_l3_id", "imported_incidents", ["l3_id"])


def downgrade() -> None:
    op.drop_index("ix_imported_incidents_l3_id", table_name="imported_incidents")
    op.drop_index("ix_imported_incidents_incident_id", table_name="imported_incidents")
    op.drop_table("imported_incidents")
