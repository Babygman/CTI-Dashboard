"""add remediation actions and immutable action history

Revision ID: 20260723_01
Revises: 20260723_00
Create Date: 2026-07-23
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql


revision: str = "20260723_01"
down_revision: Union[str, Sequence[str], None] = "20260723_00"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DATETIME_TYPE = sa.DateTime().with_variant(mssql.DATETIME2(), "mssql")


def upgrade() -> None:
    op.create_table(
        "RemediationActions",
        sa.Column("ActionId", sa.Integer(), primary_key=True),
        sa.Column(
            "ThreatId",
            sa.Integer(),
            sa.ForeignKey("Threats.ThreatId"),
            nullable=False,
        ),
        sa.Column("Title", sa.Unicode(255), nullable=False),
        sa.Column("Description", sa.UnicodeText(), nullable=True),
        sa.Column("ActionType", sa.Unicode(20), nullable=False),
        sa.Column("Priority", sa.Unicode(20), nullable=False),
        sa.Column(
            "Status",
            sa.Unicode(20),
            nullable=False,
            server_default=sa.text("'Open'"),
        ),
        sa.Column("Owner", sa.Unicode(200), nullable=True),
        sa.Column("DueDate", sa.Date(), nullable=True),
        sa.Column(
            "ApprovalStatus",
            sa.Unicode(20),
            nullable=False,
            server_default=sa.text("'Not Required'"),
        ),
        sa.Column("TicketReference", sa.Unicode(255), nullable=True),
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
        sa.Column("CompletedAt", DATETIME_TYPE, nullable=True),
        sa.CheckConstraint(
            "ActionType IN "
            "('Patch','Mitigate','Monitor','Investigate','Notify','Other')",
            name="CK_RemediationActions_ActionType",
        ),
        sa.CheckConstraint(
            "Priority IN ('Critical','High','Medium','Low')",
            name="CK_RemediationActions_Priority",
        ),
        sa.CheckConstraint(
            "Status IN "
            "('Open','In Progress','Blocked','Completed','Cancelled')",
            name="CK_RemediationActions_Status",
        ),
        sa.CheckConstraint(
            "ApprovalStatus IN "
            "('Not Required','Pending','Approved','Rejected')",
            name="CK_RemediationActions_ApprovalStatus",
        ),
        sa.UniqueConstraint(
            "ThreatId",
            "ActionType",
            "Title",
            name="UQ_RemediationActions_ThreatTypeTitle",
        ),
    )
    op.create_index(
        "IX_RemediationActions_ThreatId",
        "RemediationActions",
        ["ThreatId"],
    )
    op.create_index(
        "IX_RemediationActions_Status_DueDate",
        "RemediationActions",
        ["Status", "DueDate"],
    )
    op.create_index(
        "IX_RemediationActions_Owner",
        "RemediationActions",
        ["Owner"],
    )

    op.create_table(
        "RemediationActionHistory",
        sa.Column(
            "HistoryId",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            primary_key=True,
        ),
        sa.Column(
            "ActionId",
            sa.Integer(),
            sa.ForeignKey(
                "RemediationActions.ActionId",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("ChangeType", sa.Unicode(30), nullable=False),
        sa.Column("FieldName", sa.Unicode(50), nullable=True),
        sa.Column("OldValue", sa.UnicodeText(), nullable=True),
        sa.Column("NewValue", sa.UnicodeText(), nullable=True),
        sa.Column(
            "ChangedAt",
            DATETIME_TYPE,
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
    )
    op.create_index(
        "IX_RemediationActionHistory_ActionId_ChangedAt",
        "RemediationActionHistory",
        ["ActionId", "ChangedAt"],
    )


def downgrade() -> None:
    op.drop_index(
        "IX_RemediationActionHistory_ActionId_ChangedAt",
        table_name="RemediationActionHistory",
    )
    op.drop_table("RemediationActionHistory")
    op.drop_index(
        "IX_RemediationActions_Owner",
        table_name="RemediationActions",
    )
    op.drop_index(
        "IX_RemediationActions_Status_DueDate",
        table_name="RemediationActions",
    )
    op.drop_index(
        "IX_RemediationActions_ThreatId",
        table_name="RemediationActions",
    )
    op.drop_table("RemediationActions")
