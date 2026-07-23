import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations


MIGRATION_PATH = (
    Path(__file__).parents[1]
    / "migrations"
    / "versions"
    / "20260723_03_collection_worker_leases.py"
)


def load_migration():
    spec = importlib.util.spec_from_file_location(
        "collection_worker_migration", MIGRATION_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CollectionWorkerMigrationTests(unittest.TestCase):
    def setUp(self):
        self.engine = sa.create_engine("sqlite://")
        self.connection = self.engine.connect()
        self.connection.execute(
            sa.text(
                'CREATE TABLE "Sources" ('
                '"SourceId" INTEGER PRIMARY KEY, '
                '"Enabled" BOOLEAN NOT NULL)'
            )
        )
        self.connection.execute(
            sa.text(
                'CREATE TABLE "CollectionRuns" ('
                '"CollectionRunId" INTEGER PRIMARY KEY, '
                '"SourceId" INTEGER NOT NULL, '
                '"Status" VARCHAR(20) NOT NULL)'
            )
        )
        self.connection.execute(
            sa.text(
                'INSERT INTO "Sources" ("SourceId", "Enabled") VALUES (1, 1)'
            )
        )
        self.operations = Operations(
            MigrationContext.configure(self.connection)
        )
        self.migration = load_migration()

    def tearDown(self):
        self.connection.close()
        self.engine.dispose()

    def test_upgrade_backfills_and_downgrade_removes_lease_columns(self):
        with patch.object(self.migration, "op", self.operations):
            self.migration.upgrade()

        columns = {
            column["name"]
            for column in sa.inspect(self.connection).get_columns("Sources")
        }
        self.assertTrue(
            {
                "NextRunAt",
                "LeaseOwner",
                "LeaseExpiresAt",
                "LastHeartbeatAt",
            }.issubset(columns)
        )
        next_run = self.connection.scalar(
            sa.text(
                'SELECT "NextRunAt" FROM "Sources" WHERE "SourceId" = 1'
            )
        )
        self.assertIsNotNone(next_run)
        indexes = {
            index["name"]
            for index in sa.inspect(self.connection).get_indexes("Sources")
        }
        self.assertIn("IX_Sources_Enabled_NextRunAt", indexes)
        self.assertIn("IX_Sources_LeaseExpiresAt", indexes)
        run_indexes = {
            index["name"]: index
            for index in sa.inspect(self.connection).get_indexes(
                "CollectionRuns"
            )
        }
        self.assertTrue(
            run_indexes["UX_CollectionRuns_SourceId_Running"]["unique"]
        )

        with patch.object(self.migration, "op", self.operations):
            self.migration.downgrade()
        columns = {
            column["name"]
            for column in sa.inspect(self.connection).get_columns("Sources")
        }
        self.assertNotIn("NextRunAt", columns)


if __name__ == "__main__":
    unittest.main()
