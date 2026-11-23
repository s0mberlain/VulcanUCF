"""Implementation status of detection requests (PROJ-1)

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-20 12:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detection_request_states",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "system_id",
            sa.Integer(),
            sa.ForeignKey("systems.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key", sa.String(40), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "open",
                "in_progress",
                "implemented",
                "rejected",
                "not_feasible",
                name="request_status",
                native_enum=False,
                length=32,
                validate_strings=True,
            ),
            nullable=False,
        ),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("link_l2_id", sa.Integer(), nullable=True),
        sa.Column("link_l3_id", sa.Integer(), nullable=True),
        sa.Column("link_code", sa.String(64), nullable=True),
        sa.Column("updated_by", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("system_id", "key", name="uq_detection_request_system_key"),
    )
    op.create_index(
        "ix_detection_request_states_system_id", "detection_request_states", ["system_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_detection_request_states_system_id", table_name="detection_request_states")
    op.drop_table("detection_request_states")
