import os
import unittest

from sqlalchemy import create_engine, inspect, text

from config import Config


SQL_SERVER_ENABLED = (
    os.getenv("CTI_SQL_SERVER_INTEGRATION", "").strip() == "1"
)


@unittest.skipUnless(
    SQL_SERVER_ENABLED,
    "Set CTI_SQL_SERVER_INTEGRATION=1 for the SQL Server CI gate.",
)
class SQLServerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()

    def test_complete_schema_and_current_revision(self):
        expected = {
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
        with self.engine.connect() as connection:
            self.assertEqual(set(inspect(connection).get_table_names()), expected)
            self.assertEqual(
                connection.scalar(
                    text("SELECT version_num FROM alembic_version")
                ),
                "20260723_02",
            )

    def test_sql_server_column_types(self):
        with self.engine.connect() as connection:
            rows = connection.execute(
                text(
                    """
                    SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE
                    FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE
                        (TABLE_NAME = 'Threats'
                         AND COLUMN_NAME = 'CreatedAt')
                        OR
                        (TABLE_NAME = 'CollectionRuns'
                         AND COLUMN_NAME = 'CollectionRunId')
                    """
                )
            ).all()
        types = {(table, column): data_type for table, column, data_type in rows}
        self.assertEqual(types[("Threats", "CreatedAt")], "datetime2")
        self.assertEqual(
            types[("CollectionRuns", "CollectionRunId")], "bigint"
        )

    def test_filtered_indexes_exist(self):
        with self.engine.connect() as connection:
            rows = connection.execute(
                text(
                    """
                    SELECT name, has_filter
                    FROM sys.indexes
                    WHERE name IN (
                        'UX_SourceItems_SourceId_ExternalId',
                        'UX_ThreatCVEs_OnePrimary'
                    )
                    """
                )
            ).all()
        filters = {name: bool(has_filter) for name, has_filter in rows}
        self.assertEqual(
            filters,
            {
                "UX_SourceItems_SourceId_ExternalId": True,
                "UX_ThreatCVEs_OnePrimary": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
