import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.dialects import mssql


PATH = (
    Path(__file__).parents[1]
    / "migrations"
    / "versions"
    / "20260723_04_canonical_threats.py"
)


def load_migration():
    spec = importlib.util.spec_from_file_location(
        "canonical_threat_migration", PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CanonicalThreatMigrationTests(unittest.TestCase):
    def setUp(self):
        self.engine = sa.create_engine("sqlite://")
        self.connection = self.engine.connect()
        self.connection.execute(
            sa.text(
                'CREATE TABLE "Sources" ('
                '"SourceId" INTEGER PRIMARY KEY)'
            )
        )
        self.connection.execute(
            sa.text(
                'CREATE TABLE "Threats" ('
                '"ThreatId" INTEGER PRIMARY KEY, "PublishedDate" DATETIME, '
                '"Severity" VARCHAR(20), "Title" VARCHAR(255) NOT NULL, '
                '"Summary" TEXT, "CreatedAt" DATETIME, '
                '"Source" VARCHAR(100), "ReferenceUrl" VARCHAR(1000))'
            )
        )
        self.connection.execute(
            sa.text(
                'CREATE TABLE "SourceItems" ('
                '"SourceItemId" INTEGER PRIMARY KEY, '
                '"ThreatId" INTEGER, "SourceId" INTEGER NOT NULL, '
                '"ExternalId" VARCHAR(500), "PublishedDate" DATETIME, '
                '"FirstSeenAt" DATETIME, "Title" VARCHAR(500), '
                '"RawContent" TEXT, "ContentHash" CHAR(64))'
            )
        )
        self.connection.execute(
            sa.text(
                "INSERT INTO Sources (SourceId) VALUES (1);"
            )
        )
        self.connection.execute(
            sa.text(
                "INSERT INTO Threats "
                "(ThreatId, Title, Severity, CreatedAt, Source) "
                "VALUES (1, 'Observed threat', 'High', "
                "'2026-07-23', 'NVD'), "
                "(2, 'Legacy threat', 'Medium', "
                "'2026-07-22', 'Manual')"
            )
        )
        self.connection.execute(
            sa.text(
                "INSERT INTO SourceItems "
                "(SourceItemId, ThreatId, SourceId, ExternalId, "
                "FirstSeenAt, Title, RawContent, ContentHash) "
                "VALUES (1, 1, 1, 'NVD-1', '2026-07-23', "
                "'NVD original', '{\"product\":\"Edge\"}', :hash)"
            ),
            {"hash": "a" * 64},
        )
        self.operations = Operations(
            MigrationContext.configure(self.connection)
        )
        self.migration = load_migration()

    def tearDown(self):
        self.connection.close()
        self.engine.dispose()

    def test_upgrade_backfills_all_threats_and_downgrade(self):
        with patch.object(self.migration, "op", self.operations):
            self.migration.upgrade()

        rows = self.connection.execute(
            sa.text(
                "SELECT ThreatId, SourceId, ExternalId "
                "FROM ThreatObservations ORDER BY ThreatId"
            )
        ).all()
        self.assertEqual(rows, [(1, 1, "NVD-1"), (2, None, None)])
        indexes = {
            row["name"]
            for row in sa.inspect(self.connection).get_indexes(
                "ThreatObservations"
            )
        }
        self.assertIn(
            "IX_ThreatObservations_ThreatId_PublishedDate", indexes
        )
        self.assertIn(
            "UX_ThreatObservations_SourceId_ExternalId", indexes
        )

        with patch.object(self.migration, "op", self.operations):
            self.migration.downgrade()
        self.assertNotIn(
            "ThreatObservations",
            sa.inspect(self.connection).get_table_names(),
        )

    def test_sql_server_types_compile(self):
        self.assertEqual(
            str(
                self.migration.DATETIME_TYPE.compile(
                    dialect=mssql.dialect()
                )
            ),
            "DATETIME2",
        )
        self.assertEqual(
            str(
                self.migration.BIGINT_IDENTITY.compile(
                    dialect=mssql.dialect()
                )
            ),
            "BIGINT",
        )


if __name__ == "__main__":
    unittest.main()
