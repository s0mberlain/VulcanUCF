"""Test rounds, history and collaboration setting (PROJ-4)

Revision ID: 0023
Revises: 0022
Create Date: 2026-11-22 20:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _enum(name: str, *values: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, length=32, validate_strings=True)


def upgrade() -> None:
    with op.batch_alter_table("campaigns") as batch:
        batch.add_column(
            sa.Column("collaboration", sa.String(16), nullable=False, server_default="hidden")
        )
    op.create_table(
        "test_rounds",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "test_id",
            sa.Integer(),
            sa.ForeignKey("test_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("opened_by", sa.String(64), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "exec_status",
            _enum("test_status", "not_run", "executed", "not_executable"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_what", sa.Text(), nullable=False),
        sa.Column("red_notes", sa.Text(), nullable=False),
        sa.Column("red_by", sa.String(64), nullable=True),
        sa.Column("red_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "outcome",
            _enum("test_outcome", "blocked", "alerted", "logged", "not_detected"),
            nullable=True,
        ),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("blue_notes", sa.Text(), nullable=False),
        sa.Column("blue_by", sa.String(64), nullable=True),
        sa.Column("blue_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("red_version", sa.Integer(), nullable=False),
        sa.Column("blue_version", sa.Integer(), nullable=False),
        sa.UniqueConstraint("test_id", "number"),
    )
    op.create_index("ix_test_rounds_test_id", "test_rounds", ["test_id"])
    op.create_table(
        "round_detections",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "round_id",
            sa.Integer(),
            sa.ForeignKey("test_rounds.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "item_id",
            sa.Integer(),
            sa.ForeignKey("reference_items.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("name", sa.String(255), nullable=False),
    )
    op.create_index("ix_round_detections_round_id", "round_detections", ["round_id"])
    op.create_index("ix_round_detections_item_id", "round_detections", ["item_id"])
    op.create_table(
        "test_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "test_id",
            sa.Integer(),
            sa.ForeignKey("test_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("round_number", sa.Integer(), nullable=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("side", sa.String(8), nullable=False),
        sa.Column("author", sa.String(64), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("removed_by", sa.String(64), nullable=True),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_test_events_test_id", "test_events", ["test_id"])
    op.create_index("ix_test_events_at", "test_events", ["at"])
    with op.batch_alter_table("test_attachments") as batch:
        batch.add_column(sa.Column("round_id", sa.Integer(), nullable=True))
        batch.create_foreign_key(
            "fk_test_attachments_round_id_test_rounds",
            "test_rounds",
            ["round_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_index("ix_test_attachments_round_id", ["round_id"])

    # every existing test becomes a test with one round holding its execution and result
    bind = op.get_bind()
    tests = sa.table(
        "test_cases",
        sa.column("id"),
        sa.column("created_by"),
        sa.column("created_at"),
        sa.column("exec_status"),
        sa.column("executed_at"),
        sa.column("red_notes"),
        sa.column("red_by"),
        sa.column("red_at"),
        sa.column("outcome"),
        sa.column("detected_at"),
        sa.column("blue_notes"),
        sa.column("blue_by"),
        sa.column("blue_at"),
        sa.column("red_version"),
        sa.column("blue_version"),
    )
    rounds = sa.table(
        "test_rounds",
        sa.column("id"),
        sa.column("test_id"),
        sa.column("number"),
        sa.column("opened_by"),
        sa.column("opened_at"),
        sa.column("exec_status"),
        sa.column("started_at"),
        sa.column("ended_at"),
        sa.column("executed_what"),
        sa.column("red_notes"),
        sa.column("red_by"),
        sa.column("red_at"),
        sa.column("outcome"),
        sa.column("detected_at"),
        sa.column("blue_notes"),
        sa.column("blue_by"),
        sa.column("blue_at"),
        sa.column("red_version"),
        sa.column("blue_version"),
    )
    for t in bind.execute(sa.select(tests)).mappings().all():
        bind.execute(
            rounds.insert().values(
                test_id=t["id"],
                number=1,
                opened_by=t["created_by"],
                opened_at=t["created_at"],
                exec_status=t["exec_status"],
                started_at=t["executed_at"],
                ended_at=None,
                executed_what="",
                red_notes=t["red_notes"],
                red_by=t["red_by"],
                red_at=t["red_at"],
                outcome=t["outcome"],
                detected_at=t["detected_at"],
                blue_notes=t["blue_notes"],
                blue_by=t["blue_by"],
                blue_at=t["blue_at"],
                red_version=t["red_version"],
                blue_version=t["blue_version"],
            )
        )
        round_id = bind.execute(
            sa.text("SELECT id FROM test_rounds WHERE test_id = :t AND number = 1"),
            {"t": t["id"]},
        ).scalar_one()
        bind.execute(
            sa.text("UPDATE test_attachments SET round_id = :r WHERE test_id = :t"),
            {"r": round_id, "t": t["id"]},
        )


def downgrade() -> None:
    with op.batch_alter_table("test_attachments") as batch:
        batch.drop_index("ix_test_attachments_round_id")
        batch.drop_constraint("fk_test_attachments_round_id_test_rounds", type_="foreignkey")
        batch.drop_column("round_id")
    op.drop_index("ix_test_events_at", table_name="test_events")
    op.drop_index("ix_test_events_test_id", table_name="test_events")
    op.drop_table("test_events")
    op.drop_index("ix_round_detections_item_id", table_name="round_detections")
    op.drop_index("ix_round_detections_round_id", table_name="round_detections")
    op.drop_table("round_detections")
    op.drop_index("ix_test_rounds_test_id", table_name="test_rounds")
    op.drop_table("test_rounds")
    with op.batch_alter_table("campaigns") as batch:
        batch.drop_column("collaboration")
