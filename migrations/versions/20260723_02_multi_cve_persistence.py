"""add normalized CVEs and threat relationships

Revision ID: 20260723_02
Revises: 20260723_01
Create Date: 2026-07-23
"""
import logging
import re
from datetime import datetime
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mssql


revision: str = "20260723_02"
down_revision: Union[str, Sequence[str], None] = "20260723_01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DATETIME_TYPE = sa.DateTime().with_variant(mssql.DATETIME2(), "mssql")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
LOGGER = logging.getLogger("alembic.runtime.migration")


def upgrade() -> None:
    op.create_table(
        "CVEs",
        sa.Column("CVEId", sa.Integer(), primary_key=True),
        sa.Column("CVECode", sa.Unicode(30), nullable=False),
        sa.Column("Description", sa.UnicodeText(), nullable=True),
        sa.Column("PublishedAt", DATETIME_TYPE, nullable=True),
        sa.Column("ModifiedAt", DATETIME_TYPE, nullable=True),
        sa.Column("CVSSScore", sa.Numeric(4, 1), nullable=True),
        sa.Column("CVSSSeverity", sa.Unicode(20), nullable=True),
        sa.Column("CWE", sa.Unicode(100), nullable=True),
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
        sa.CheckConstraint(
            "CVECode = UPPER(CVECode)",
            name="CK_CVEs_CVECode_Uppercase",
        ),
        sa.UniqueConstraint("CVECode", name="UQ_CVEs_CVECode"),
    )
    op.create_index("IX_CVEs_CVSSSeverity", "CVEs", ["CVSSSeverity"])
    op.create_index("IX_CVEs_CVSSScore", "CVEs", ["CVSSScore"])

    op.create_table(
        "ThreatCVEs",
        sa.Column(
            "ThreatId",
            sa.Integer(),
            sa.ForeignKey("Threats.ThreatId", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "CVEId",
            sa.Integer(),
            sa.ForeignKey("CVEs.CVEId", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "IsPrimary",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("Source", sa.Unicode(100), nullable=True),
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
    )
    op.create_index("IX_ThreatCVEs_CVEId", "ThreatCVEs", ["CVEId"])
    op.create_index(
        "UX_ThreatCVEs_OnePrimary",
        "ThreatCVEs",
        ["ThreatId"],
        unique=True,
        mssql_where=sa.text("IsPrimary = 1"),
        sqlite_where=sa.text("IsPrimary = 1"),
    )
    _backfill()


def _backfill() -> None:
    connection = op.get_bind()
    metadata = sa.MetaData()
    threats = sa.Table("Threats", metadata, autoload_with=connection)
    cves = sa.Table("CVEs", metadata, autoload_with=connection)
    threat_cves = sa.Table("ThreatCVEs", metadata, autoload_with=connection)
    optional = {
        name for name in ("Summary", "PublishedDate", "ModifiedDate", "CVSS",
                          "Severity", "Source", "CreatedAt")
        if name in threats.c
    }
    # pyodbc does not allow another command on a connection while a result
    # cursor is still active. Materialize every source row before performing
    # any CVE lookups or inserts.
    rows = connection.execute(
        sa.select(
            threats.c.ThreatId,
            threats.c.CVE,
            *(threats.c[name] for name in sorted(optional)),
        ).where(threats.c.CVE.is_not(None))
    ).mappings().all()

    valid_rows = []
    invalid = 0
    for row in rows:
        code = str(row["CVE"] or "").strip().upper()
        if not CVE_PATTERN.fullmatch(code):
            invalid += 1
            continue
        valid_rows.append((row, code))

    now = datetime.utcnow()

    # Load existing keys into memory once. This also makes the backfill safe
    # when invoked against a partially populated migration target.
    existing_cve_rows = connection.execute(
        sa.select(cves.c.CVEId, cves.c.CVECode)
    ).all()
    cve_ids_by_code = {
        code: cve_id for cve_id, code in existing_cve_rows
    }
    representative_rows = {}
    for row, code in valid_rows:
        representative_rows.setdefault(code, row)
    missing_codes = [
        code for code in representative_rows if code not in cve_ids_by_code
    ]
    if missing_codes:
        connection.execute(
            cves.insert(),
            [
                {
                    "CVECode": code,
                    "Description": representative_rows[code].get("Summary"),
                    "PublishedAt": representative_rows[code].get(
                        "PublishedDate"
                    ),
                    "ModifiedAt": representative_rows[code].get(
                        "ModifiedDate"
                    ),
                    "CVSSScore": representative_rows[code].get("CVSS"),
                    "CVSSSeverity": representative_rows[code].get("Severity"),
                    "CreatedAt": now,
                    "UpdatedAt": now,
                }
                for code in missing_codes
            ],
        )

        # Re-read once after the set-based insert instead of relying on
        # per-row INSERT/OUTPUT result cursors under SQL Server.
        cve_ids_by_code = {
            code: cve_id
            for cve_id, code in connection.execute(
                sa.select(cves.c.CVEId, cves.c.CVECode)
            ).all()
        }

    existing_links = set(
        connection.execute(
            sa.select(threat_cves.c.ThreatId, threat_cves.c.CVEId)
        ).all()
    )
    link_values = []
    for row, code in valid_rows:
        cve_id = cve_ids_by_code[code]
        key = (row["ThreatId"], cve_id)
        if key in existing_links:
            continue
        first_seen = row.get("CreatedAt") or now
        link_values.append(
            {
                "ThreatId": row["ThreatId"],
                "CVEId": cve_id,
                "IsPrimary": True,
                "Source": row.get("Source"),
                "FirstSeenAt": first_seen,
                "LastSeenAt": row.get("ModifiedDate") or first_seen,
            }
        )
        existing_links.add(key)
    if link_values:
        connection.execute(threat_cves.insert(), link_values)

    duplicates = len(valid_rows) - len(missing_codes)
    LOGGER.info(
        "CVE backfill complete: migrated=%d invalid_ignored=%d "
        "existing_cves_reused=%d",
        len(link_values),
        invalid,
        duplicates,
    )


def downgrade() -> None:
    op.drop_index(
        "UX_ThreatCVEs_OnePrimary", table_name="ThreatCVEs"
    )
    op.drop_index("IX_ThreatCVEs_CVEId", table_name="ThreatCVEs")
    op.drop_table("ThreatCVEs")
    op.drop_index("IX_CVEs_CVSSScore", table_name="CVEs")
    op.drop_index("IX_CVEs_CVSSSeverity", table_name="CVEs")
    op.drop_table("CVEs")
