"""Tests, campaigns, test library and red team accounts (PROJ-3)

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-22 12:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _enum(name: str, *values: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, length=32, validate_strings=True)


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(
            sa.Column(
                "expiry_follows_campaign",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )

    op.create_table(
        "test_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("technique", sa.String(32), nullable=False),
        sa.Column("procedure", sa.Text(), nullable=False),
        sa.Column("tools", sa.String(500), nullable=False),
        sa.Column("prerequisites", sa.Text(), nullable=False),
        sa.Column("expected_detection", sa.Text(), nullable=False),
        sa.Column("uses", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_test_templates_technique", "test_templates", ["technique"])

    op.create_table(
        "campaigns",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("planned_start", sa.Date(), nullable=False),
        sa.Column("planned_end", sa.Date(), nullable=False),
        sa.Column(
            "status",
            _enum("campaign_status", "planned", "running", "closed"),
            nullable=False,
        ),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "campaign_accounts",
        sa.Column(
            "campaign_id",
            sa.Integer(),
            sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
        ),
    )

    op.create_table(
        "test_cases",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "campaign_id",
            sa.Integer(),
            sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("technique", sa.String(32), nullable=False),
        sa.Column("procedure", sa.Text(), nullable=False),
        sa.Column("tools", sa.String(500), nullable=False),
        sa.Column("prerequisites", sa.Text(), nullable=False),
        sa.Column("expected_detection", sa.Text(), nullable=False),
        sa.Column("template_id", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_by_red_team", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "exec_status",
            _enum("test_status", "not_run", "executed", "not_executable"),
            nullable=False,
        ),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("red_version", sa.Integer(), nullable=False),
        sa.Column("blue_version", sa.Integer(), nullable=False),
    )
    op.create_index("ix_test_cases_campaign_id", "test_cases", ["campaign_id"])
    op.create_index("ix_test_cases_technique", "test_cases", ["technique"])

    op.create_table(
        "test_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "test_id",
            sa.Integer(),
            sa.ForeignKey("test_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "l3_id",
            sa.Integer(),
            sa.ForeignKey("l3_use_cases.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("rule_code", sa.String(64), nullable=False),
        sa.Column("rule_name", sa.String(255), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
    )
    op.create_index("ix_test_rules_test_id", "test_rules", ["test_id"])
    op.create_index("ix_test_rules_l3_id", "test_rules", ["l3_id"])

    op.create_table(
        "test_attachments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "test_id",
            sa.Integer(),
            sa.ForeignKey("test_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("side", sa.String(8), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("content_type", sa.String(128), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column("uploaded_by", sa.String(64), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_test_attachments_test_id", "test_attachments", ["test_id"])

    op.create_table(
        "gap_acceptances",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "l3_id",
            sa.Integer(),
            sa.ForeignKey("l3_use_cases.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("technique", sa.String(32), nullable=False),
        sa.Column("scope", sa.String(128), nullable=False),
        sa.Column(
            "test_id",
            sa.Integer(),
            sa.ForeignKey("test_cases.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("accepted_by", sa.String(64), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_gap_acceptances_l3_id", "gap_acceptances", ["l3_id"])

    with op.batch_alter_table("verifications") as batch:
        batch.add_column(sa.Column("test_id", sa.Integer(), nullable=True))
        batch.create_foreign_key(
            "fk_verifications_test_id_test_cases",
            "test_cases",
            ["test_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_index("ix_verifications_test_id", ["test_id"])


def downgrade() -> None:
    with op.batch_alter_table("verifications") as batch:
        batch.drop_index("ix_verifications_test_id")
        batch.drop_constraint("fk_verifications_test_id_test_cases", type_="foreignkey")
        batch.drop_column("test_id")
    op.drop_index("ix_gap_acceptances_l3_id", table_name="gap_acceptances")
    op.drop_table("gap_acceptances")
    op.drop_index("ix_test_attachments_test_id", table_name="test_attachments")
    op.drop_table("test_attachments")
    op.drop_index("ix_test_rules_l3_id", table_name="test_rules")
    op.drop_index("ix_test_rules_test_id", table_name="test_rules")
    op.drop_table("test_rules")
    op.drop_index("ix_test_cases_technique", table_name="test_cases")
    op.drop_index("ix_test_cases_campaign_id", table_name="test_cases")
    op.drop_table("test_cases")
    op.drop_table("campaign_accounts")
    op.drop_table("campaigns")
    op.drop_index("ix_test_templates_technique", table_name="test_templates")
    op.drop_table("test_templates")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("expiry_follows_campaign")
        batch.drop_column("expires_at")
