"""Tasks on L2 use cases and L3 rules (issue #74)

Revision ID: 0025
Revises: 0024
Create Date: 2026-11-24 16:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tasks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "l2_id",
            sa.Integer(),
            sa.ForeignKey("l2_use_cases.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "l3_id",
            sa.Integer(),
            sa.ForeignKey("l3_use_cases.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("assignee", sa.String(64), nullable=True),
        sa.Column("done_by", sa.String(64), nullable=True),
        sa.Column("done_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("(l2_id IS NULL) <> (l3_id IS NULL)", name="ck_tasks_one_owner"),
    )
    op.create_index("ix_tasks_l2_id", "tasks", ["l2_id"])
    op.create_index("ix_tasks_l3_id", "tasks", ["l3_id"])
    op.create_index("ix_tasks_status", "tasks", ["status"])
    op.create_index("ix_tasks_assignee", "tasks", ["assignee"])


def downgrade() -> None:
    op.drop_index("ix_tasks_assignee", table_name="tasks")
    op.drop_index("ix_tasks_status", table_name="tasks")
    op.drop_index("ix_tasks_l3_id", table_name="tasks")
    op.drop_index("ix_tasks_l2_id", table_name="tasks")
    op.drop_table("tasks")
