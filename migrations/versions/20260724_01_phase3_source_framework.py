"""Configure Phase 3 Microsoft MSRC and JPCERT sources.

Revision ID: 20260724_01
Revises: 20260724_00
Create Date: 2026-07-24
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260724_01"
down_revision: Union[str, Sequence[str], None] = "20260724_00"
branch_labels = None
depends_on = None

MSRC_FEED_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
JPCERT_FEED_URL = "https://www.jpcert.or.jp/rss/jpcert.rdf"


def _sources_table():
    return sa.table(
        "Sources",
        sa.column("SourceId", sa.Integer()),
        sa.column("SourceName", sa.Unicode(200)),
        sa.column("SourceType", sa.Unicode(50)),
        sa.column("BaseUrl", sa.Unicode(1000)),
        sa.column("FeedUrl", sa.Unicode(1000)),
        sa.column("Enabled", sa.Boolean()),
        sa.column("CollectionIntervalMinutes", sa.Integer()),
        sa.column("TimeoutSeconds", sa.Integer()),
        sa.column("Priority", sa.SmallInteger()),
        sa.column("CreatedAt", sa.DateTime()),
        sa.column("UpdatedAt", sa.DateTime()),
    )


def upgrade() -> None:
    connection = op.get_bind()
    sources = _sources_table()
    connection.execute(
        sources.update()
        .where(
            sa.func.lower(sources.c.SourceName)
            == "microsoft security response center"
        )
        .values(
            SourceType="MicrosoftMsrc",
            BaseUrl="https://msrc.microsoft.com",
            FeedUrl=MSRC_FEED_URL,
        )
    )

    jpcert_id = connection.scalar(
        sa.select(sources.c.SourceId)
        .where(sa.func.lower(sources.c.SourceName) == "jpcert")
        .limit(1)
    )
    if jpcert_id is None:
        connection.execute(
            sources.insert().values(
                SourceName="JPCERT",
                SourceType="Jpcert",
                BaseUrl="https://www.jpcert.or.jp",
                FeedUrl=JPCERT_FEED_URL,
                Enabled=False,
                CollectionIntervalMinutes=60,
                TimeoutSeconds=30,
                Priority=50,
                CreatedAt=sa.func.current_timestamp(),
                UpdatedAt=sa.func.current_timestamp(),
            )
        )
    else:
        connection.execute(
            sources.update()
            .where(sources.c.SourceId == jpcert_id)
            .values(
                SourceType="Jpcert",
                BaseUrl="https://www.jpcert.or.jp",
                FeedUrl=JPCERT_FEED_URL,
            )
        )


def downgrade() -> None:
    connection = op.get_bind()
    sources = _sources_table()
    connection.execute(
        sources.update()
        .where(
            sa.func.lower(sources.c.SourceName)
            == "microsoft security response center"
        )
        .values(
            SourceType="Microsoft",
            FeedUrl=None,
        )
    )
    connection.execute(
        sources.update()
        .where(sa.func.lower(sources.c.SourceName) == "jpcert")
        .values(
            Enabled=False,
            FeedUrl=None,
        )
    )
