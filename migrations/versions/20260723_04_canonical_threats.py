"""add canonical threat observations

Revision ID: 20260723_04
Revises: 20260723_03
Create Date: 2026-07-23
"""

import hashlib
import json
from datetime import datetime

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql


revision = "20260723_04"
down_revision = "20260723_03"
branch_labels = None
depends_on = None

DATETIME_TYPE = sa.DateTime().with_variant(mssql.DATETIME2(), "mssql")
BIGINT_IDENTITY = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def _payload_hash(value):
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def _backfill(connection):
    # Materialize every result before inserts for SQL Server/pyodbc.
    source_rows = connection.execute(
        sa.text(
            """
            SELECT SourceItemId, ThreatId, SourceId, ExternalId,
                   PublishedDate, FirstSeenAt, Title, RawContent,
                   ContentHash
            FROM SourceItems
            WHERE ThreatId IS NOT NULL
            ORDER BY SourceItemId
            """
        )
    ).mappings().fetchall()
    threat_rows = connection.execute(
        sa.text(
            """
            SELECT ThreatId, PublishedDate, Severity, Title, Summary,
                   CreatedAt, Source, ReferenceUrl
            FROM Threats
            ORDER BY ThreatId
            """
        )
    ).mappings().fetchall()

    observed_threat_ids = set()
    inserts = []
    for row in source_rows:
        observed_threat_ids.add(row["ThreatId"])
        inserts.append(
            {
                "ThreatId": row["ThreatId"],
                "SourceId": row["SourceId"],
                "ExternalId": row["ExternalId"],
                "PublishedDate": row["PublishedDate"],
                "ObservedDate": row["FirstSeenAt"],
                "Severity": None,
                "Title": row["Title"] or "Untitled source observation",
                "Summary": None,
                "RawPayloadHash": (
                    _payload_hash(row["RawContent"])
                    if row["RawContent"]
                    else row["ContentHash"]
                ),
                "MatchMethod": "Backfill",
                "MatchConfidence": 1,
                "CreatedAt": row["FirstSeenAt"],
            }
        )

    for row in threat_rows:
        if row["ThreatId"] in observed_threat_ids:
            continue
        canonical_payload = json.dumps(
            {
                "source": row["Source"],
                "reference_url": row["ReferenceUrl"],
                "title": row["Title"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        created_at = row["CreatedAt"] or datetime.utcnow()
        inserts.append(
            {
                "ThreatId": row["ThreatId"],
                "SourceId": None,
                "ExternalId": None,
                "PublishedDate": row["PublishedDate"],
                "ObservedDate": created_at,
                "Severity": row["Severity"],
                "Title": row["Title"],
                "Summary": row["Summary"],
                "RawPayloadHash": _payload_hash(canonical_payload),
                "MatchMethod": "Backfill",
                "MatchConfidence": 1,
                "CreatedAt": created_at,
            }
        )

    if inserts:
        connection.execute(
            sa.text(
                """
                INSERT INTO ThreatObservations (
                    ThreatId, SourceId, ExternalId, PublishedDate,
                    ObservedDate, Severity, Title, Summary,
                    RawPayloadHash, MatchMethod, MatchConfidence, CreatedAt
                ) VALUES (
                    :ThreatId, :SourceId, :ExternalId, :PublishedDate,
                    :ObservedDate, :Severity, :Title, :Summary,
                    :RawPayloadHash, :MatchMethod, :MatchConfidence, :CreatedAt
                )
                """
            ),
            inserts,
        )


def upgrade():
    op.create_table(
        "ThreatObservations",
        sa.Column(
            "ObservationId",
            BIGINT_IDENTITY,
            sa.Identity(start=1, increment=1),
            primary_key=True,
        ),
        sa.Column("ThreatId", sa.Integer(), nullable=False),
        sa.Column("SourceId", sa.Integer(), nullable=True),
        sa.Column("ExternalId", sa.Unicode(length=500), nullable=True),
        sa.Column("PublishedDate", DATETIME_TYPE, nullable=True),
        sa.Column("ObservedDate", DATETIME_TYPE, nullable=False),
        sa.Column("Severity", sa.Unicode(length=20), nullable=True),
        sa.Column("Title", sa.Unicode(length=500), nullable=False),
        sa.Column("Summary", sa.UnicodeText(), nullable=True),
        sa.Column("RawPayloadHash", sa.CHAR(length=64), nullable=False),
        sa.Column(
            "MatchMethod",
            sa.Unicode(length=30),
            nullable=False,
            server_default="Backfill",
        ),
        sa.Column(
            "MatchConfidence",
            sa.Numeric(5, 4),
            nullable=False,
            server_default=sa.text("1.0"),
        ),
        sa.Column("CreatedAt", DATETIME_TYPE, nullable=False),
        sa.CheckConstraint(
            "MatchConfidence BETWEEN 0.0 AND 1.0",
            name="CK_ThreatObservations_MatchConfidence",
        ),
        sa.ForeignKeyConstraint(
            ["ThreatId"],
            ["Threats.ThreatId"],
            name="FK_ThreatObservations_Threats",
        ),
        sa.ForeignKeyConstraint(
            ["SourceId"],
            ["Sources.SourceId"],
            name="FK_ThreatObservations_Sources",
        ),
    )
    op.create_index(
        "IX_ThreatObservations_ThreatId_PublishedDate",
        "ThreatObservations",
        ["ThreatId", "PublishedDate"],
    )
    op.create_index(
        "IX_ThreatObservations_SourceId_ExternalId",
        "ThreatObservations",
        ["SourceId", "ExternalId"],
    )
    op.create_index(
        "IX_ThreatObservations_RawPayloadHash",
        "ThreatObservations",
        ["RawPayloadHash"],
    )
    op.create_index(
        "UX_ThreatObservations_SourceId_ExternalId",
        "ThreatObservations",
        ["SourceId", "ExternalId"],
        unique=True,
        mssql_where=sa.text("ExternalId IS NOT NULL"),
        sqlite_where=sa.text("ExternalId IS NOT NULL"),
    )
    _backfill(op.get_bind())


def downgrade():
    op.drop_table("ThreatObservations")
