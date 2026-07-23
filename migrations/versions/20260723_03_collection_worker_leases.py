"""add scheduled collection lease state

Revision ID: 20260723_03
Revises: 20260723_02
Create Date: 2026-07-23
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql


revision = "20260723_03"
down_revision = "20260723_02"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "Sources",
        sa.Column(
            "NextRunAt",
            sa.DateTime().with_variant(mssql.DATETIME2(), "mssql"),
            nullable=True,
        ),
    )
    op.add_column(
        "Sources",
        sa.Column("LeaseOwner", sa.Unicode(length=255), nullable=True),
    )
    op.add_column(
        "Sources",
        sa.Column(
            "LeaseExpiresAt",
            sa.DateTime().with_variant(mssql.DATETIME2(), "mssql"),
            nullable=True,
        ),
    )
    op.add_column(
        "Sources",
        sa.Column(
            "LastHeartbeatAt",
            sa.DateTime().with_variant(mssql.DATETIME2(), "mssql"),
            nullable=True,
        ),
    )

    # Existing enabled sources become immediately eligible after deployment.
    utc_now = (
        "SYSUTCDATETIME()"
        if op.get_bind().dialect.name == "mssql"
        else "CURRENT_TIMESTAMP"
    )
    op.execute(
        sa.text(
            f"UPDATE Sources SET NextRunAt = {utc_now} "
            "WHERE Enabled = 1 AND NextRunAt IS NULL"
        )
    )
    op.create_index(
        "IX_Sources_Enabled_NextRunAt",
        "Sources",
        ["Enabled", "NextRunAt"],
        unique=False,
    )
    op.create_index(
        "IX_Sources_LeaseExpiresAt",
        "Sources",
        ["LeaseExpiresAt"],
        unique=False,
    )
    op.create_index(
        "UX_CollectionRuns_SourceId_Running",
        "CollectionRuns",
        ["SourceId"],
        unique=True,
        mssql_where=sa.text("Status = N'Running'"),
        sqlite_where=sa.text("Status = 'Running'"),
    )


def downgrade():
    op.drop_index(
        "UX_CollectionRuns_SourceId_Running",
        table_name="CollectionRuns",
    )
    op.drop_index("IX_Sources_LeaseExpiresAt", table_name="Sources")
    op.drop_index("IX_Sources_Enabled_NextRunAt", table_name="Sources")
    op.drop_column("Sources", "LastHeartbeatAt")
    op.drop_column("Sources", "LeaseExpiresAt")
    op.drop_column("Sources", "LeaseOwner")
    op.drop_column("Sources", "NextRunAt")
