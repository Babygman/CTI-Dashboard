"""baseline the complete pre-remediation application schema

Revision ID: 20260723_00
Revises:
Create Date: 2026-07-23
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql


revision: str = "20260723_00"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DATETIME_TYPE = sa.DateTime().with_variant(mssql.DATETIME2(), "mssql")
BIGINT_IDENTITY = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "Vendors",
        sa.Column("VendorId", sa.Integer(), primary_key=True),
        sa.Column("VendorName", sa.Unicode(100), nullable=False),
        sa.Column("Category", sa.Unicode(100), nullable=True),
        sa.Column("Website", sa.Unicode(255), nullable=True),
        sa.Column(
            "Enabled",
            sa.Boolean(),
            nullable=True,
            server_default=sa.text("1"),
        ),
    )

    op.create_table(
        "CatalogProducts",
        sa.Column("CatalogProductId", sa.Integer(), primary_key=True),
        sa.Column("VendorName", sa.Unicode(100), nullable=False),
        sa.Column("ProductName", sa.Unicode(200), nullable=False),
        sa.Column("ProductFamily", sa.Unicode(100), nullable=True),
        sa.Column("TechnologyCategory", sa.Unicode(100), nullable=True),
        sa.Column("Description", sa.UnicodeText(), nullable=True),
        sa.Column(
            "Active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "CreatedAt",
            DATETIME_TYPE,
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.Column(
            "UpdatedAt",
            DATETIME_TYPE,
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.UniqueConstraint(
            "VendorName",
            "ProductName",
            name="UQ_CatalogProducts_VendorName_ProductName",
        ),
    )
    op.create_index(
        "IX_CatalogProducts_VendorName",
        "CatalogProducts",
        ["VendorName"],
    )
    op.create_index(
        "IX_CatalogProducts_ProductName",
        "CatalogProducts",
        ["ProductName"],
    )
    op.create_index(
        "IX_CatalogProducts_Active",
        "CatalogProducts",
        ["Active"],
    )

    op.create_table(
        "Sources",
        sa.Column("SourceId", sa.Integer(), primary_key=True),
        sa.Column("SourceName", sa.Unicode(200), nullable=False),
        sa.Column("SourceType", sa.Unicode(50), nullable=False),
        sa.Column("BaseUrl", sa.Unicode(1000), nullable=True),
        sa.Column("FeedUrl", sa.Unicode(1000), nullable=True),
        sa.Column(
            "Enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "CollectionIntervalMinutes",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("60"),
        ),
        sa.Column(
            "TimeoutSeconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("30"),
        ),
        sa.Column(
            "Priority",
            sa.SmallInteger(),
            nullable=False,
            server_default=sa.text("50"),
        ),
        sa.Column("LastSuccessfulCollection", DATETIME_TYPE, nullable=True),
        sa.Column("LastCollectionStatus", sa.Unicode(20), nullable=True),
        sa.Column(
            "CreatedAt",
            DATETIME_TYPE,
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.Column(
            "UpdatedAt",
            DATETIME_TYPE,
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.UniqueConstraint("SourceName", name="UQ_Sources_SourceName"),
        sa.CheckConstraint(
            "CollectionIntervalMinutes > 0",
            name="CK_Sources_CollectionIntervalMinutes",
        ),
        sa.CheckConstraint(
            "TimeoutSeconds > 0",
            name="CK_Sources_TimeoutSeconds",
        ),
        sa.CheckConstraint(
            "Priority BETWEEN 0 AND 100",
            name="CK_Sources_Priority",
        ),
    )
    op.create_index("IX_Sources_Enabled", "Sources", ["Enabled"])

    op.create_table(
        "SystemSettings",
        sa.Column("SettingId", sa.Integer(), primary_key=True),
        sa.Column("SettingKey", sa.String(100), nullable=False),
        sa.Column("SettingValue", sa.Text(), nullable=True),
        sa.Column(
            "SettingGroup",
            sa.String(50),
            nullable=False,
        ),
        sa.Column("Description", sa.String(255), nullable=True),
        sa.Column("IsActive", sa.Boolean(), nullable=False),
        sa.Column("CreatedAt", sa.DateTime(), nullable=False),
        sa.Column("UpdatedAt", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_SystemSettings_SettingKey",
        "SystemSettings",
        ["SettingKey"],
        unique=True,
    )
    op.create_index(
        "ix_SystemSettings_SettingGroup",
        "SystemSettings",
        ["SettingGroup"],
    )

    op.create_table(
        "Threats",
        sa.Column("ThreatId", sa.Integer(), primary_key=True),
        sa.Column("Title", sa.Unicode(255), nullable=False),
        sa.Column(
            "VendorId",
            sa.Integer(),
            sa.ForeignKey("Vendors.VendorId"),
            nullable=True,
        ),
        sa.Column("Source", sa.Unicode(100), nullable=True),
        sa.Column("Severity", sa.Unicode(20), nullable=True),
        sa.Column("CVE", sa.Unicode(50), nullable=True),
        sa.Column("CVSS", sa.Numeric(4, 1), nullable=True),
        sa.Column(
            "KEV",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("PublishedDate", DATETIME_TYPE, nullable=True),
        sa.Column("ReferenceUrl", sa.Unicode(1000), nullable=True),
        sa.Column("Summary", sa.UnicodeText(), nullable=True),
        sa.Column("Recommendation", sa.UnicodeText(), nullable=True),
        sa.Column(
            "CreatedAt",
            DATETIME_TYPE,
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.Column("ModifiedDate", DATETIME_TYPE, nullable=True),
        sa.CheckConstraint(
            "CVSS IS NULL OR CVSS BETWEEN 0.0 AND 10.0",
            name="CK_Threats_CVSS",
        ),
    )

    op.create_table(
        "ProductAliases",
        sa.Column("ProductAliasId", sa.Integer(), primary_key=True),
        sa.Column(
            "CatalogProductId",
            sa.Integer(),
            sa.ForeignKey(
                "CatalogProducts.CatalogProductId",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("Alias", sa.Unicode(200), nullable=False),
        sa.Column("AliasType", sa.Unicode(50), nullable=True),
        sa.Column(
            "Active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.Column(
            "CreatedAt",
            DATETIME_TYPE,
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.UniqueConstraint(
            "CatalogProductId",
            "Alias",
            name="UQ_ProductAliases_CatalogProductId_Alias",
        ),
    )
    op.create_index(
        "IX_ProductAliases_Alias",
        "ProductAliases",
        ["Alias"],
    )

    op.create_table(
        "Assets",
        sa.Column("AssetId", sa.Integer(), primary_key=True),
        sa.Column("AssetName", sa.Unicode(200), nullable=False),
        sa.Column("Vendor", sa.Unicode(100), nullable=True),
        sa.Column("Product", sa.Unicode(200), nullable=True),
        sa.Column("Version", sa.Unicode(100), nullable=True),
        sa.Column("AssetType", sa.Unicode(100), nullable=True),
        sa.Column(
            "Critical",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("Environment", sa.Unicode(100), nullable=True),
        sa.Column("Owner", sa.Unicode(200), nullable=True),
        sa.Column("Location", sa.Unicode(255), nullable=True),
        sa.Column(
            "Status",
            sa.Unicode(50),
            nullable=False,
            server_default=sa.text("'Active'"),
        ),
        sa.Column("Notes", sa.UnicodeText(), nullable=True),
        sa.Column(
            "CreatedAt",
            DATETIME_TYPE,
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.Column(
            "UpdatedAt",
            DATETIME_TYPE,
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.Column(
            "CatalogProductId",
            sa.Integer(),
            sa.ForeignKey("CatalogProducts.CatalogProductId"),
            nullable=True,
        ),
    )
    op.create_index(
        "IX_Assets_CatalogProductId",
        "Assets",
        ["CatalogProductId"],
    )

    op.create_table(
        "CollectionRuns",
        sa.Column("CollectionRunId", BIGINT_IDENTITY, primary_key=True),
        sa.Column(
            "SourceId",
            sa.Integer(),
            sa.ForeignKey("Sources.SourceId"),
            nullable=False,
        ),
        sa.Column(
            "StartedAt",
            DATETIME_TYPE,
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.Column("FinishedAt", DATETIME_TYPE, nullable=True),
        sa.Column(
            "Status",
            sa.Unicode(20),
            nullable=False,
            server_default=sa.text("'Running'"),
        ),
        sa.Column(
            "ItemsFetched",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "ItemsCreated",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "ItemsUpdated",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "ItemsSkipped",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("ErrorMessage", sa.UnicodeText(), nullable=True),
        sa.Column("WorkerName", sa.Unicode(200), nullable=True),
        sa.CheckConstraint(
            "Status IN ('Running', 'Success', 'Partial', 'Failed')",
            name="CK_CollectionRuns_Status",
        ),
        sa.CheckConstraint(
            "ItemsFetched >= 0 AND ItemsCreated >= 0 "
            "AND ItemsUpdated >= 0 AND ItemsSkipped >= 0",
            name="CK_CollectionRuns_ItemCounts",
        ),
    )
    op.create_index(
        "IX_CollectionRuns_SourceId_StartedAt",
        "CollectionRuns",
        ["SourceId", "StartedAt"],
    )

    op.create_table(
        "SourceItems",
        sa.Column("SourceItemId", BIGINT_IDENTITY, primary_key=True),
        sa.Column(
            "SourceId",
            sa.Integer(),
            sa.ForeignKey("Sources.SourceId"),
            nullable=False,
        ),
        sa.Column(
            "CollectionRunId",
            BIGINT_IDENTITY,
            sa.ForeignKey("CollectionRuns.CollectionRunId"),
            nullable=True,
        ),
        sa.Column("ExternalId", sa.Unicode(500), nullable=True),
        sa.Column("CVE", sa.Unicode(50), nullable=True),
        sa.Column("ContentHash", sa.CHAR(64), nullable=False),
        sa.Column("Title", sa.Unicode(500), nullable=True),
        sa.Column("SourceUrl", sa.Unicode(1000), nullable=True),
        sa.Column("PublishedDate", DATETIME_TYPE, nullable=True),
        sa.Column("SourceModifiedDate", DATETIME_TYPE, nullable=True),
        sa.Column("NormalizedMetadata", sa.UnicodeText(), nullable=True),
        sa.Column("MatchMethod", sa.Unicode(30), nullable=True),
        sa.Column("RawContent", sa.UnicodeText(), nullable=True),
        sa.Column(
            "ProcessingStatus",
            sa.Unicode(20),
            nullable=False,
            server_default=sa.text("'Pending'"),
        ),
        sa.Column("ErrorMessage", sa.UnicodeText(), nullable=True),
        sa.Column(
            "FirstSeenAt",
            DATETIME_TYPE,
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.Column(
            "LastSeenAt",
            DATETIME_TYPE,
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.Column(
            "ThreatId",
            sa.Integer(),
            sa.ForeignKey("Threats.ThreatId"),
            nullable=True,
        ),
        sa.CheckConstraint(
            "ProcessingStatus IN "
            "('Pending', 'Processed', 'Duplicate', 'Failed')",
            name="CK_SourceItems_ProcessingStatus",
        ),
    )
    op.create_index("IX_SourceItems_SourceId", "SourceItems", ["SourceId"])
    op.create_index(
        "IX_SourceItems_ContentHash",
        "SourceItems",
        ["ContentHash"],
    )
    op.create_index(
        "IX_SourceItems_ProcessingStatus",
        "SourceItems",
        ["ProcessingStatus"],
    )
    op.create_index(
        "IX_SourceItems_CollectionRunId",
        "SourceItems",
        ["CollectionRunId"],
    )
    op.create_index(
        "IX_SourceItems_CVE",
        "SourceItems",
        ["CVE"],
        mssql_where=sa.text("CVE IS NOT NULL"),
    )
    op.create_index(
        "IX_SourceItems_ThreatId_SourceId",
        "SourceItems",
        ["ThreatId", "SourceId"],
        mssql_include=["FirstSeenAt", "LastSeenAt"],
    )
    op.create_index(
        "UX_SourceItems_SourceId_ExternalId",
        "SourceItems",
        ["SourceId", "ExternalId"],
        unique=True,
        mssql_where=sa.text("ExternalId IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "UX_SourceItems_SourceId_ExternalId",
        table_name="SourceItems",
    )
    op.drop_index(
        "IX_SourceItems_ThreatId_SourceId",
        table_name="SourceItems",
    )
    op.drop_index("IX_SourceItems_CVE", table_name="SourceItems")
    op.drop_index(
        "IX_SourceItems_CollectionRunId",
        table_name="SourceItems",
    )
    op.drop_index(
        "IX_SourceItems_ProcessingStatus",
        table_name="SourceItems",
    )
    op.drop_index(
        "IX_SourceItems_ContentHash",
        table_name="SourceItems",
    )
    op.drop_index(
        "IX_SourceItems_SourceId",
        table_name="SourceItems",
    )
    op.drop_table("SourceItems")

    op.drop_index(
        "IX_CollectionRuns_SourceId_StartedAt",
        table_name="CollectionRuns",
    )
    op.drop_table("CollectionRuns")

    op.drop_index("IX_Assets_CatalogProductId", table_name="Assets")
    op.drop_table("Assets")

    op.drop_index(
        "IX_ProductAliases_Alias",
        table_name="ProductAliases",
    )
    op.drop_table("ProductAliases")

    op.drop_table("Threats")

    op.drop_index(
        "ix_SystemSettings_SettingGroup",
        table_name="SystemSettings",
    )
    op.drop_index(
        "ix_SystemSettings_SettingKey",
        table_name="SystemSettings",
    )
    op.drop_table("SystemSettings")

    op.drop_index("IX_Sources_Enabled", table_name="Sources")
    op.drop_table("Sources")

    op.drop_index(
        "IX_CatalogProducts_Active",
        table_name="CatalogProducts",
    )
    op.drop_index(
        "IX_CatalogProducts_ProductName",
        table_name="CatalogProducts",
    )
    op.drop_index(
        "IX_CatalogProducts_VendorName",
        table_name="CatalogProducts",
    )
    op.drop_table("CatalogProducts")

    op.drop_table("Vendors")
