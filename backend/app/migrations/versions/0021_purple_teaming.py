"""Purple teaming (VECTR-style): assessments, campaigns, test cases, detections, evidence and
the template library

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-18 12:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "pt_assessments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("environment", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("start_date", sa.Date(), nullable=True),
        sa.Column("end_date", sa.Date(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "planned",
                "in_progress",
                "completed",
                name="pt_assessment_status",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("previous_id", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["previous_id"],
            ["pt_assessments.id"],
            name=op.f("fk_pt_assessments_previous_id_pt_assessments"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pt_assessments")),
    )
    op.create_table(
        "pt_campaign_templates",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("name_key", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("template_ids", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pt_campaign_templates")),
        sa.UniqueConstraint("name_key", name=op.f("uq_pt_campaign_templates_name_key")),
    )
    op.create_table(
        "pt_templates",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("name_key", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("techniques", sa.JSON(), nullable=False),
        sa.Column("tactic", sa.String(length=64), nullable=False),
        sa.Column("platforms", sa.JSON(), nullable=False),
        sa.Column("executor", sa.String(length=64), nullable=False),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("cleanup", sa.Text(), nullable=False),
        sa.Column("operator_guidance", sa.Text(), nullable=False),
        sa.Column("expected_defenses", sa.JSON(), nullable=False),
        sa.Column("detection_steps", sa.Text(), nullable=False),
        sa.Column("prevention_steps", sa.Text(), nullable=False),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("source_ref", sa.String(length=128), nullable=False),
        sa.Column("archived", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pt_templates")),
        sa.UniqueConstraint("name_key", name=op.f("uq_pt_templates_name_key")),
    )
    op.create_index(
        op.f("ix_pt_templates_source_ref"), "pt_templates", ["source_ref"], unique=False
    )
    op.create_table(
        "pt_campaigns",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("assessment_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["pt_assessments.id"],
            name=op.f("fk_pt_campaigns_assessment_id_pt_assessments"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pt_campaigns")),
    )
    op.create_index(
        op.f("ix_pt_campaigns_assessment_id"), "pt_campaigns", ["assessment_id"], unique=False
    )
    op.create_table(
        "pt_test_cases",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("campaign_id", sa.Integer(), nullable=False),
        sa.Column("template_id", sa.Integer(), nullable=True),
        sa.Column("lineage_key", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("techniques", sa.JSON(), nullable=False),
        sa.Column("tactic", sa.String(length=64), nullable=False),
        sa.Column("platforms", sa.JSON(), nullable=False),
        sa.Column("executor", sa.String(length=64), nullable=False),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("cleanup", sa.Text(), nullable=False),
        sa.Column("operator_guidance", sa.Text(), nullable=False),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column(
            "red_status",
            sa.Enum(
                "planned",
                "in_progress",
                "executed",
                "not_executed",
                name="pt_red_status",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("red_assignee", sa.String(length=64), nullable=False),
        sa.Column("attack_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attack_stop", sa.DateTime(timezone=True), nullable=True),
        sa.Column("targets", sa.JSON(), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("red_tools", sa.JSON(), nullable=False),
        sa.Column("red_notes", sa.Text(), nullable=False),
        sa.Column("red_version", sa.Integer(), nullable=False),
        sa.Column("red_updated_by", sa.String(length=64), nullable=False),
        sa.Column(
            "blue_status",
            sa.Enum(
                "waiting", "in_review", "done", name="pt_blue_status", native_enum=False, length=32
            ),
            nullable=False,
        ),
        sa.Column("blue_assignee", sa.String(length=64), nullable=False),
        sa.Column("blue_notes", sa.Text(), nullable=False),
        sa.Column("detection_steps", sa.Text(), nullable=False),
        sa.Column("prevention_steps", sa.Text(), nullable=False),
        sa.Column(
            "outcome_override",
            sa.Enum(
                "blocked",
                "alerted",
                "logged_central",
                "logged_local",
                "none",
                "not_applicable",
                "tbd",
                name="pt_outcome",
                native_enum=False,
                length=32,
            ),
            nullable=True,
        ),
        sa.Column("blue_version", sa.Integer(), nullable=False),
        sa.Column("blue_updated_by", sa.String(length=64), nullable=False),
        sa.Column("plan_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["pt_campaigns.id"],
            name=op.f("fk_pt_test_cases_campaign_id_pt_campaigns"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["template_id"],
            ["pt_templates.id"],
            name=op.f("fk_pt_test_cases_template_id_pt_templates"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pt_test_cases")),
    )
    op.create_index(
        op.f("ix_pt_test_cases_campaign_id"), "pt_test_cases", ["campaign_id"], unique=False
    )
    op.create_index(
        op.f("ix_pt_test_cases_lineage_key"), "pt_test_cases", ["lineage_key"], unique=False
    )
    op.create_index(
        op.f("ix_pt_test_cases_template_id"), "pt_test_cases", ["template_id"], unique=False
    )
    op.create_table(
        "pt_attachments",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("test_case_id", sa.Integer(), nullable=False),
        sa.Column("side", sa.String(length=8), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("content_type", sa.String(length=128), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column("uploaded_by", sa.String(length=64), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["test_case_id"],
            ["pt_test_cases.id"],
            name=op.f("fk_pt_attachments_test_case_id_pt_test_cases"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pt_attachments")),
    )
    op.create_index(
        op.f("ix_pt_attachments_test_case_id"), "pt_attachments", ["test_case_id"], unique=False
    )
    op.create_table(
        "pt_detections",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("test_case_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("l3_id", sa.Integer(), nullable=True),
        sa.Column("rule_code", sa.String(length=64), nullable=False),
        sa.Column("tool", sa.String(length=255), nullable=False),
        sa.Column(
            "outcome",
            sa.Enum(
                "blocked",
                "alerted",
                "logged_central",
                "logged_local",
                "none",
                "not_applicable",
                "tbd",
                name="pt_outcome",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("expected", sa.Boolean(), nullable=False),
        sa.Column("alert_name", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["l3_id"],
            ["l3_use_cases.id"],
            name=op.f("fk_pt_detections_l3_id_l3_use_cases"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["test_case_id"],
            ["pt_test_cases.id"],
            name=op.f("fk_pt_detections_test_case_id_pt_test_cases"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pt_detections")),
    )
    op.create_index(op.f("ix_pt_detections_l3_id"), "pt_detections", ["l3_id"], unique=False)
    op.create_index(
        op.f("ix_pt_detections_test_case_id"), "pt_detections", ["test_case_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_pt_detections_test_case_id"), table_name="pt_detections")
    op.drop_index(op.f("ix_pt_detections_l3_id"), table_name="pt_detections")
    op.drop_table("pt_detections")
    op.drop_index(op.f("ix_pt_attachments_test_case_id"), table_name="pt_attachments")
    op.drop_table("pt_attachments")
    op.drop_index(op.f("ix_pt_test_cases_template_id"), table_name="pt_test_cases")
    op.drop_index(op.f("ix_pt_test_cases_lineage_key"), table_name="pt_test_cases")
    op.drop_index(op.f("ix_pt_test_cases_campaign_id"), table_name="pt_test_cases")
    op.drop_table("pt_test_cases")
    op.drop_index(op.f("ix_pt_campaigns_assessment_id"), table_name="pt_campaigns")
    op.drop_table("pt_campaigns")
    op.drop_index(op.f("ix_pt_templates_source_ref"), table_name="pt_templates")
    op.drop_table("pt_templates")
    op.drop_table("pt_campaign_templates")
    op.drop_table("pt_assessments")
