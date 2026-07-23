"""Verify that a migrated SQL Server database contains the complete schema."""

import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect, text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import Config


EXPECTED_TABLES = {
    "Assets",
    "CatalogProducts",
    "CollectionRuns",
    "CVEs",
    "ProductAliases",
    "RemediationActionHistory",
    "RemediationActions",
    "SourceItems",
    "Sources",
    "SystemSettings",
    "ThreatCVEs",
    "Threats",
    "Vendors",
    "alembic_version",
}
EXPECTED_HEAD = "20260723_02"


def main():
    engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)
    try:
        with engine.connect() as connection:
            tables = set(inspect(connection).get_table_names())
            if tables != EXPECTED_TABLES:
                missing = sorted(EXPECTED_TABLES - tables)
                unexpected = sorted(tables - EXPECTED_TABLES)
                raise SystemExit(
                    f"SQL Server schema mismatch: missing={missing}, "
                    f"unexpected={unexpected}"
                )
            current = connection.scalar(
                text("SELECT version_num FROM alembic_version")
            )
            if current != EXPECTED_HEAD:
                raise SystemExit(
                    f"Expected Alembic head {EXPECTED_HEAD}; found {current}"
                )
    finally:
        engine.dispose()
    print(
        f"SQL Server schema contains all {len(EXPECTED_TABLES) - 1} "
        f"application tables at {EXPECTED_HEAD}."
    )


if __name__ == "__main__":
    main()
