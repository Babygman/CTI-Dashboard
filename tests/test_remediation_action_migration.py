import importlib.util
import unittest
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.dialects import mssql


MIGRATION_PATH = (
    Path(__file__).parents[1]
    / "migrations"
    / "versions"
    / "20260723_01_remediation_actions.py"
)


def load_migration():
    spec = importlib.util.spec_from_file_location(
        "remediation_action_migration",
        MIGRATION_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RemediationActionMigrationTests(unittest.TestCase):
    def setUp(self):
        self.engine = sa.create_engine("sqlite://")
        metadata = sa.MetaData()
        sa.Table(
            "Threats",
            metadata,
            sa.Column("ThreatId", sa.Integer, primary_key=True),
        )
        metadata.create_all(self.engine)

    def tearDown(self):
        self.engine.dispose()

    def test_upgrade_and_downgrade(self):
        migration = load_migration()
        with self.engine.begin() as connection:
            context = MigrationContext.configure(connection)
            migration.op = Operations(context)
            migration.upgrade()

            inspector = sa.inspect(connection)
            self.assertIn(
                "RemediationActions",
                inspector.get_table_names(),
            )
            self.assertIn(
                "RemediationActionHistory",
                inspector.get_table_names(),
            )
            action_columns = {
                column["name"]
                for column in inspector.get_columns(
                    "RemediationActions"
                )
            }
            self.assertEqual(
                action_columns,
                {
                    "ActionId",
                    "ThreatId",
                    "Title",
                    "Description",
                    "ActionType",
                    "Priority",
                    "Status",
                    "Owner",
                    "DueDate",
                    "ApprovalStatus",
                    "TicketReference",
                    "Notes",
                    "CreatedAt",
                    "UpdatedAt",
                    "CompletedAt",
                },
            )

            migration.downgrade()
            inspector = sa.inspect(connection)
            self.assertNotIn(
                "RemediationActions",
                inspector.get_table_names(),
            )
            self.assertNotIn(
                "RemediationActionHistory",
                inspector.get_table_names(),
            )
            self.assertIn("Threats", inspector.get_table_names())

    def test_model_ddl_compiles_for_sql_server(self):
        migration = load_migration()
        self.assertEqual(migration.revision, "20260723_01")
        self.assertEqual(migration.down_revision, "20260723_00")
        compiled = str(
            migration.DATETIME_TYPE.compile(
                dialect=mssql.dialect()
            )
        )
        self.assertEqual(compiled, "DATETIME2")


if __name__ == "__main__":
    unittest.main()
