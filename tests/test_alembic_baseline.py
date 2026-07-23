import importlib.util
import unittest
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.dialects import mssql


VERSIONS = Path(__file__).parents[1] / "migrations" / "versions"
MIGRATION_FILES = (
    "20260723_00_application_baseline.py",
    "20260723_01_remediation_actions.py",
    "20260723_02_multi_cve_persistence.py",
    "20260723_03_collection_worker_leases.py",
    "20260723_04_canonical_threats.py",
)
APPLICATION_TABLES = {
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
    "ThreatObservations",
    "Threats",
    "Vendors",
}


def load_migration(filename):
    path = VERSIONS / filename
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AlembicBaselineTests(unittest.TestCase):
    def setUp(self):
        self.engine = sa.create_engine("sqlite://")
        self.connection = self.engine.connect()
        self.context = MigrationContext.configure(self.connection)
        self.operations = Operations(self.context)
        self.migrations = [
            load_migration(filename) for filename in MIGRATION_FILES
        ]
        for migration in self.migrations:
            migration.op = self.operations

    def tearDown(self):
        self.connection.close()
        self.engine.dispose()

    def _table_names(self):
        names = set(sa.inspect(self.connection).get_table_names())
        self.connection.commit()
        return names

    def _upgrade_head(self):
        for migration in self.migrations:
            migration.upgrade()
        self.connection.commit()

    def _downgrade_base(self):
        for migration in reversed(self.migrations):
            migration.downgrade()
        self.connection.commit()

    def test_clean_upgrade_downgrade_and_reupgrade(self):
        self.assertEqual(self._table_names(), set())

        self._upgrade_head()
        self.assertEqual(self._table_names(), APPLICATION_TABLES)

        self._downgrade_base()
        self.assertEqual(self._table_names(), set())

        self._upgrade_head()
        self.assertEqual(self._table_names(), APPLICATION_TABLES)

    def test_revision_dependency_graph(self):
        self.assertEqual(
            [
                (migration.revision, migration.down_revision)
                for migration in self.migrations
            ],
            [
                ("20260723_00", None),
                ("20260723_01", "20260723_00"),
                ("20260723_02", "20260723_01"),
                ("20260723_03", "20260723_02"),
                ("20260723_04", "20260723_03"),
            ],
        )

    def test_baseline_uses_sql_server_compatible_types(self):
        baseline = self.migrations[0]
        self.assertEqual(
            str(baseline.DATETIME_TYPE.compile(dialect=mssql.dialect())),
            "DATETIME2",
        )
        self.assertEqual(
            str(baseline.BIGINT_IDENTITY.compile(dialect=mssql.dialect())),
            "BIGINT",
        )


if __name__ == "__main__":
    unittest.main()
