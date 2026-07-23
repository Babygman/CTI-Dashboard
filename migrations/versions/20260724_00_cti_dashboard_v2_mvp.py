"""CTI Dashboard v2 MVP news, impact, and awareness

Revision ID: 20260724_00
Revises: 20260723_04
Create Date: 2026-07-24
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql

revision: str = "20260724_00"
down_revision: Union[str, Sequence[str], None] = "20260723_04"
branch_labels = None
depends_on = None
DATETIME_TYPE = sa.DateTime().with_variant(mssql.DATETIME2(), "mssql")


def upgrade() -> None:
    op.add_column(
        "Assets", sa.Column("Quantity", sa.Integer(), nullable=False, server_default=sa.text("1"))
    )
    op.add_column("Assets", sa.Column("Department", sa.Unicode(200), nullable=True))
    if op.get_bind().dialect.name != "sqlite":
        op.create_check_constraint("CK_Assets_Quantity", "Assets", "Quantity >= 1")

    op.create_table(
        "NewsItems",
        sa.Column("NewsItemId", sa.Integer(), primary_key=True),
        sa.Column("Title", sa.Unicode(500), nullable=False),
        sa.Column("Source", sa.Unicode(200), nullable=False),
        sa.Column("ReferenceUrl", sa.Unicode(1000), nullable=False),
        sa.Column("PublishedDate", DATETIME_TYPE),
        sa.Column("Summary", sa.UnicodeText()),
        sa.Column("ThaiSummary", sa.UnicodeText()),
        sa.Column("Vendor", sa.Unicode(100)),
        sa.Column("Product", sa.Unicode(200)),
        sa.Column("CVE", sa.Unicode(50)),
        sa.Column("Severity", sa.Unicode(20)),
        sa.Column("ThreatType", sa.Unicode(50)),
        sa.Column("UserImpact", sa.UnicodeText()),
        sa.Column("ITImpact", sa.UnicodeText()),
        sa.Column("IsRelevant", sa.Boolean()),
        sa.Column("RecommendationType", sa.Unicode(40)),
        sa.Column("RecommendationReason", sa.UnicodeText()),
        sa.Column("CreatedAt", DATETIME_TYPE, nullable=False, server_default=sa.text("SYSUTCDATETIME()")),
        sa.Column("UpdatedAt", DATETIME_TYPE),
    )
    op.create_index("IX_NewsItems_PublishedDate", "NewsItems", ["PublishedDate"])
    op.create_index("IX_NewsItems_Relevance", "NewsItems", ["IsRelevant"])

    op.create_table(
        "ThreatAssessments",
        sa.Column("ThreatAssessmentId", sa.Integer(), primary_key=True),
        sa.Column("ThreatId", sa.Integer(), sa.ForeignKey("Threats.ThreatId", ondelete="CASCADE"), nullable=False),
        sa.Column("AssetId", sa.Integer(), sa.ForeignKey("Assets.AssetId", ondelete="CASCADE"), nullable=False),
        sa.Column("ImpactStatus", sa.Unicode(30), nullable=False),
        sa.Column("MatchReason", sa.UnicodeText(), nullable=False),
        sa.Column("RecommendationType", sa.Unicode(40), nullable=False),
        sa.Column("RecommendationReason", sa.UnicodeText(), nullable=False),
        sa.Column("Reviewed", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("UpdatedAt", DATETIME_TYPE, nullable=False, server_default=sa.text("SYSUTCDATETIME()")),
        sa.UniqueConstraint("ThreatId", "AssetId", name="UQ_ThreatAssessments_ThreatId_AssetId"),
    )
    op.create_index("IX_ThreatAssessments_Status_Action", "ThreatAssessments", ["ImpactStatus", "RecommendationType"])

    op.create_table(
        "AwarenessRecords",
        sa.Column("AwarenessRecordId", sa.Integer(), primary_key=True),
        sa.Column("ThreatId", sa.Integer(), sa.ForeignKey("Threats.ThreatId")),
        sa.Column("NewsItemId", sa.Integer(), sa.ForeignKey("NewsItems.NewsItemId")),
        sa.Column("Title", sa.Unicode(500), nullable=False),
        sa.Column("ThaiExplanation", sa.UnicodeText(), nullable=False),
        sa.Column("WhatHappened", sa.UnicodeText(), nullable=False),
        sa.Column("WhoAffected", sa.UnicodeText(), nullable=False),
        sa.Column("MustDo", sa.UnicodeText(), nullable=False),
        sa.Column("MustNotDo", sa.UnicodeText(), nullable=False),
        sa.Column("ReportToIT", sa.UnicodeText(), nullable=False),
        sa.Column("ReferenceUrl", sa.Unicode(1000)),
        sa.Column("Severity", sa.Unicode(20)),
        sa.Column("Status", sa.Unicode(20), nullable=False, server_default=sa.text("'Draft'")),
        sa.Column("DocumentVersion", sa.Unicode(20), nullable=False, server_default=sa.text("'1.0'")),
        sa.Column("CreatedAt", DATETIME_TYPE, nullable=False, server_default=sa.text("SYSUTCDATETIME()")),
        sa.Column("UpdatedAt", DATETIME_TYPE),
        sa.CheckConstraint("Status IN ('Draft', 'Ready')", name="CK_AwarenessRecords_Status"),
    )
    op.create_index("IX_AwarenessRecords_Status", "AwarenessRecords", ["Status"])


def downgrade() -> None:
    op.drop_table("AwarenessRecords")
    op.drop_table("ThreatAssessments")
    op.drop_table("NewsItems")
    if op.get_bind().dialect.name != "sqlite":
        op.drop_constraint("CK_Assets_Quantity", "Assets", type_="check")
    op.drop_column("Assets", "Department")
    op.drop_column("Assets", "Quantity")
