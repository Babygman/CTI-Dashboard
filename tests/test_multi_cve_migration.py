import importlib.util
import unittest
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.dialects import mssql


PATH = Path(__file__).parents[1] / "migrations" / "versions" / "20260723_02_multi_cve_persistence.py"


def load_migration():
    spec = importlib.util.spec_from_file_location("multi_cve_migration", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MultiCVEMigrationTests(unittest.TestCase):
    def setUp(self):
        self.engine = sa.create_engine("sqlite://")
        metadata = sa.MetaData()
        self.threats = sa.Table(
            "Threats",
            metadata,
            sa.Column("ThreatId", sa.Integer, primary_key=True),
            sa.Column("CVE", sa.Unicode(50)),
            sa.Column("Summary", sa.UnicodeText),
            sa.Column("PublishedDate", sa.DateTime),
            sa.Column("ModifiedDate", sa.DateTime),
            sa.Column("CVSS", sa.Numeric(4, 1)),
            sa.Column("Severity", sa.Unicode(20)),
            sa.Column("Source", sa.Unicode(100)),
            sa.Column("CreatedAt", sa.DateTime),
        )
        metadata.create_all(self.engine)

    def tearDown(self):
        self.engine.dispose()

    def test_upgrade_backfill_invalid_handling_and_downgrade(self):
        with self.engine.begin() as connection:
            connection.execute(
                self.threats.insert(),
                [
                    {"ThreatId": 1, "CVE": "cve-2026-1234", "Source": "NVD"},
                    {"ThreatId": 2, "CVE": "not-valid", "Source": "Manual"},
                    {"ThreatId": 3, "CVE": "CVE-2026-1234", "Source": "CISA KEV"},
                ],
            )
            migration = load_migration()
            migration.op = Operations(MigrationContext.configure(connection))
            with self.assertLogs("alembic.runtime.migration", level="INFO") as logs:
                migration.upgrade()
            self.assertIn("invalid_ignored=1", "\n".join(logs.output))
            cves = sa.Table("CVEs", sa.MetaData(), autoload_with=connection)
            links = sa.Table("ThreatCVEs", sa.MetaData(), autoload_with=connection)
            self.assertEqual(connection.scalar(sa.select(sa.func.count()).select_from(cves)), 1)
            self.assertEqual(connection.scalar(sa.select(sa.func.count()).select_from(links)), 2)
            self.assertEqual(connection.scalar(sa.select(cves.c.CVECode)), "CVE-2026-1234")
            migration.downgrade()
            names = sa.inspect(connection).get_table_names()
            self.assertNotIn("CVEs", names)
            self.assertNotIn("ThreatCVEs", names)
            self.assertIn("Threats", names)

    def test_sql_server_compatibility(self):
        migration = load_migration()
        self.assertEqual(migration.down_revision, "20260723_01")
        self.assertEqual(
            str(migration.DATETIME_TYPE.compile(dialect=mssql.dialect())),
            "DATETIME2",
        )
        table = sa.Table(
            "ThreatCVEs",
            sa.MetaData(),
            sa.Column("ThreatId", sa.Integer),
            sa.Column("IsPrimary", sa.Boolean),
        )
        index = sa.Index(
            "UX_Test",
            table.c.ThreatId,
            unique=True,
            mssql_where=sa.text("IsPrimary = 1"),
        )
        compiled = str(sa.schema.CreateIndex(index).compile(dialect=mssql.dialect()))
        self.assertIn("WHERE IsPrimary = 1", compiled)


if __name__ == "__main__":
    unittest.main()
