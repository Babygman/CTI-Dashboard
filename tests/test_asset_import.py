import csv
from datetime import datetime
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy.dialects import mssql

from app.extensions import db
from app.models.asset import Asset
from app.models.catalog_product import CatalogProduct
from app.services.asset_import import (
    MAX_FILE_SIZE,
    AssetImportService,
    AssetImportValidationError,
)
from tests.support import create_test_app


HEADERS = [
    "AssetName",
    "AssetType",
    "Environment",
    "Criticality",
    "CatalogVendor",
    "CatalogProduct",
    "IPAddress",
    "Hostname",
    "OperatingSystem",
    "Owner",
    "Location",
    "Description",
    "Enabled",
]


class AssetImportTests(unittest.TestCase):
    def setUp(self):
        self.app = create_test_app()
        self.context = self.app.app_context()
        self.context.push()
        connection = db.engine.raw_connection()
        connection.create_function(
            "sysutcdatetime", 0,
            lambda: datetime.utcnow().isoformat(" ")
        )
        connection.close()
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.catalog = CatalogProduct(
            VendorName="Fortinet",
            ProductName="FortiGate",
            Active=True,
        )
        db.session.add(self.catalog)
        db.session.commit()

    def tearDown(self):
        db.session.rollback()
        db.session.remove()
        db.engine.dispose()
        self.context.pop()

    def _row(self, **overrides):
        row = {
            "AssetName": "FG200E",
            "AssetType": "Firewall",
            "Environment": "Production",
            "Criticality": "true",
            "CatalogVendor": "Fortinet",
            "CatalogProduct": "FortiGate",
            "IPAddress": "192.0.2.10",
            "Hostname": "fg200e.example.test",
            "OperatingSystem": "FortiOS",
            "Owner": "IT",
            "Location": "Bangkok",
            "Description": "Perimeter firewall",
            "Enabled": "yes",
        }
        row.update(overrides)
        return row

    def _write_csv(self, rows, headers=None, name="assets.csv"):
        path = Path(self.temp_directory.name) / name
        fieldnames = headers or HEADERS
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        return path

    def test_required_headers(self):
        headers = [header for header in HEADERS if header != "AssetName"]
        path = self._write_csv([], headers=headers)

        with self.assertRaisesRegex(
            AssetImportValidationError,
            "missing required headers: AssetName",
        ):
            AssetImportService().import_file(path)

    def test_valid_import(self):
        path = self._write_csv([self._row()])

        result = AssetImportService().import_file(path)
        asset = db.session.scalar(
            db.select(Asset).where(Asset.AssetName == "FG200E")
        )

        self.assertEqual(result["created"], 1)
        self.assertEqual(asset.CatalogProductId, self.catalog.CatalogProductId)
        self.assertEqual(asset.Vendor, "Fortinet")
        self.assertEqual(asset.Product, "FortiGate")
        self.assertTrue(asset.Critical)
        self.assertEqual(asset.Status, "Active")
        self.assertIn("IP Address: 192.0.2.10", asset.Notes)
        self.assertIn("Hostname: fg200e.example.test", asset.Notes)
        self.assertIn("Operating System: FortiOS", asset.Notes)

    def test_dry_run_writes_nothing(self):
        path = self._write_csv([self._row()])

        result = AssetImportService().import_file(path, dry_run=True)

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["created"], 1)
        self.assertEqual(
            db.session.scalar(db.select(db.func.count(Asset.AssetId))), 0
        )

    def test_duplicate_asset_updates_existing_row(self):
        existing = Asset(
            AssetName="fg200e",
            AssetType="Old",
            Critical=False,
            Environment="Test",
            Status="Active",
            Owner="Old Owner",
        )
        db.session.add(existing)
        db.session.commit()
        path = self._write_csv(
            [self._row(AssetName=" FG200E ", Owner=" New Owner ")]
        )

        result = AssetImportService().import_file(path)

        self.assertEqual(result["updated"], 1)
        self.assertEqual(
            db.session.scalar(db.select(db.func.count(Asset.AssetId))), 1
        )
        db.session.refresh(existing)
        self.assertEqual(existing.Owner, "New Owner")
        self.assertEqual(existing.AssetType, "Firewall")
        self.assertTrue(existing.Critical)

    def test_catalog_query_matches_actual_sql_server_schema(self):
        sql = str(
            AssetImportService._catalog_query().compile(
                dialect=mssql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

        self.assertIn("[CatalogProducts].[CatalogProductId]", sql)
        self.assertIn("[CatalogProducts].[VendorName]", sql)
        self.assertIn("[CatalogProducts].[ProductName]", sql)
        self.assertIn("[CatalogProducts].[Active] = 1", sql)
        self.assertNotIn("VendorId", sql)
        self.assertNotIn("Enabled", sql)

    def test_inactive_catalog_product_is_not_matched(self):
        inactive = CatalogProduct(
            VendorName="Microsoft",
            ProductName="SQL Server 2022",
            Active=False,
        )
        db.session.add(inactive)
        db.session.commit()
        path = self._write_csv(
            [
                self._row(
                    CatalogVendor=" microsoft ",
                    CatalogProduct=" sql server 2022 ",
                )
            ]
        )

        result = AssetImportService().import_file(path)

        self.assertEqual(result["skipped"], 1)
        self.assertIn(
            "Catalog Product not found",
            result["row_errors"][0]["reason"],
        )
    def test_missing_catalog_product_skips_row(self):
        path = self._write_csv(
            [self._row(CatalogProduct="Missing Product")]
        )

        result = AssetImportService().import_file(path)

        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["errors"], 1)
        self.assertIn(
            "Catalog Product not found",
            result["row_errors"][0]["reason"],
        )
        self.assertEqual(
            db.session.scalar(db.select(db.func.count(Asset.AssetId))), 0
        )

    def test_invalid_environment(self):
        path = self._write_csv([self._row(Environment="   ")])

        result = AssetImportService().import_file(path)

        self.assertEqual(result["skipped"], 1)
        self.assertEqual(
            result["row_errors"][0]["reason"],
            "Environment is required",
        )

    def test_invalid_criticality(self):
        path = self._write_csv([self._row(Criticality="Critical")])

        result = AssetImportService().import_file(path)

        self.assertEqual(result["skipped"], 1)
        self.assertIn(
            "Criticality must be one of",
            result["row_errors"][0]["reason"],
        )

    def test_invalid_enabled(self):
        path = self._write_csv([self._row(Enabled="sometimes")])

        result = AssetImportService().import_file(path)

        self.assertEqual(result["skipped"], 1)
        self.assertIn(
            "Enabled must be one of",
            result["row_errors"][0]["reason"],
        )

    def test_blank_rows_are_ignored(self):
        blank = {header: "" for header in HEADERS}
        path = self._write_csv([blank, self._row()])

        result = AssetImportService().import_file(path)

        self.assertEqual(result["total_rows"], 1)
        self.assertEqual(result["valid_rows"], 1)
        self.assertEqual(result["created"], 1)

    def test_whitespace_is_trimmed(self):
        path = self._write_csv(
            [
                self._row(
                    AssetName="  FG200E  ",
                    AssetType="  Firewall  ",
                    Environment="  Production  ",
                    Owner="  IT Operations  ",
                    Location="  Bangkok  ",
                )
            ]
        )

        AssetImportService().import_file(path)
        asset = db.session.scalar(db.select(Asset))

        self.assertEqual(asset.AssetName, "FG200E")
        self.assertEqual(asset.AssetType, "Firewall")
        self.assertEqual(asset.Environment, "Production")
        self.assertEqual(asset.Owner, "IT Operations")
        self.assertEqual(asset.Location, "Bangkok")

    def test_case_insensitive_catalog_matching(self):
        path = self._write_csv(
            [
                self._row(
                    CatalogVendor=" fOrTiNeT ",
                    CatalogProduct=" fOrTiGaTe ",
                )
            ]
        )

        result = AssetImportService().import_file(path)
        asset = db.session.scalar(db.select(Asset))

        self.assertEqual(result["created"], 1)
        self.assertEqual(asset.Vendor, "Fortinet")
        self.assertEqual(asset.Product, "FortiGate")

    def test_row_failure_does_not_stop_other_rows(self):
        path = self._write_csv(
            [
                self._row(AssetName="Invalid", Enabled="invalid"),
                self._row(AssetName="Valid Asset"),
            ]
        )

        result = AssetImportService().import_file(path)

        self.assertEqual(result["total_rows"], 2)
        self.assertEqual(result["valid_rows"], 1)
        self.assertEqual(result["created"], 1)
        self.assertEqual(result["skipped"], 1)
        self.assertIsNotNone(
            db.session.scalar(
                db.select(Asset).where(Asset.AssetName == "Valid Asset")
            )
        )

    def test_fatal_error_rolls_back_transaction(self):
        existing = Asset(
            AssetName="Existing",
            AssetType="Server",
            Critical=False,
            Environment="Test",
            Owner="Original",
            Status="Active",
        )
        db.session.add(existing)
        db.session.commit()
        path = self._write_csv(
            [
                self._row(AssetName="Existing", Owner="Changed"),
                self._row(AssetName="New Asset"),
            ]
        )
        service = AssetImportService()
        original_apply = service._apply_plan

        def apply_then_fail(plans):
            original_apply(plans)
            raise RuntimeError("fatal test error")

        with patch.object(
            service, "_apply_plan", side_effect=apply_then_fail
        ):
            with self.assertRaisesRegex(RuntimeError, "fatal test error"):
                service.import_file(path)

        db.session.expire_all()
        self.assertEqual(
            db.session.scalar(db.select(db.func.count(Asset.AssetId))), 1
        )
        persisted = db.session.scalar(
            db.select(Asset).where(Asset.AssetName == "Existing")
        )
        self.assertEqual(persisted.Owner, "Original")

    def test_file_size_limit(self):
        path = Path(self.temp_directory.name) / "oversized.csv"
        with path.open("wb") as handle:
            handle.seek(MAX_FILE_SIZE)
            handle.write(b"x")

        with self.assertRaisesRegex(
            AssetImportValidationError, "exceeds the 10 MB"
        ):
            AssetImportService().import_file(path)

    def test_missing_file(self):
        path = Path(self.temp_directory.name) / "missing.csv"

        with self.assertRaisesRegex(
            AssetImportValidationError, "does not exist"
        ):
            AssetImportService().import_file(path)

    def test_output_summary_counts(self):
        path = self._write_csv(
            [
                self._row(AssetName="Valid Asset"),
                self._row(AssetName="Invalid Asset", Enabled="invalid"),
            ]
        )

        result = self.app.test_cli_runner().invoke(
            args=["import-assets", "--file", str(path), "--dry-run"]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        for expected in (
            "Row 3: Enabled must be one of",
            "Total rows : 2",
            "Valid rows : 1",
            "Created : 1",
            "Updated : 0",
            "Skipped : 1",
            "Errors : 1",
            "Dry run status : Yes",
        ):
            self.assertIn(expected, result.output)
        self.assertEqual(
            db.session.scalar(db.select(db.func.count(Asset.AssetId))), 0
        )


if __name__ == "__main__":
    unittest.main()




