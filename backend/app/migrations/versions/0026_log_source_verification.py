"""Log source verification: owner, interval and checks per log source (issue #75)

Revision ID: 0026
Revises: 0025
Create Date: 2026-11-24 17:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: str | None = "0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "log_source_profiles",
        sa.Column(
            "item_id",
            sa.Integer(),
            sa.ForeignKey("reference_items.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("verification_interval_days", sa.Integer(), nullable=True),
        sa.Column("last_verified_at", sa.Date(), nullable=True),
        sa.Column("last_verified_by", sa.String(64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "log_source_verifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "item_id",
            sa.Integer(),
            sa.ForeignKey("reference_items.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("verified_at", sa.Date(), nullable=False),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column(
            "result",
            sa.Enum("ok", "issues", name="verification_result", native_enum=False, length=32),
            nullable=False,
        ),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("checks", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_log_source_verifications_item_id", "log_source_verifications", ["item_id"])


def downgrade() -> None:
    op.drop_index("ix_log_source_verifications_item_id", table_name="log_source_verifications")
    op.drop_table("log_source_verifications")
    op.drop_table("log_source_profiles")
