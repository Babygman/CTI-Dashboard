import unittest

from app.extensions import db
from app.models.asset import Asset
from app.models.catalog_product import CatalogProduct
from app.models.product_alias import ProductAlias

from tests.support import create_test_app


class AnalyzeImpactCliTests(unittest.TestCase):
    def setUp(self):
        self.app = create_test_app()
        with self.app.app_context():
            product = CatalogProduct(
                VendorName="Fortinet",
                ProductName="FortiGate",
                Active=True,
            )
            db.session.add(product)
            db.session.flush()
            db.session.add(
                ProductAlias(
                    CatalogProductId=product.CatalogProductId,
                    Alias="FortiOS",
                    Active=True,
                )
            )
            db.session.add_all(
                [
                    Asset(
                        AssetName="FG200E",
                        CatalogProductId=product.CatalogProductId,
                        Owner="IT",
                        Environment="Production",
                        Critical=True,
                        Status="Active",
                    ),
                    Asset(
                        AssetName="FG200E-DR",
                        CatalogProductId=product.CatalogProductId,
                        Owner="IT",
                        Environment="DR",
                        Critical=True,
                        Status="Active",
                    ),
                    Asset(
                        AssetName="FG200E-Retired",
                        CatalogProductId=product.CatalogProductId,
                        Owner="IT",
                        Environment="Legacy",
                        Critical=True,
                        Status="Retired",
                    ),
                ]
            )
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.engine.dispose()

    def test_matched_output_and_asset_order(self):
        result = self.app.test_cli_runner().invoke(
            args=[
                "analyze-impact",
                "--vendor",
                "Fortinet",
                "--product",
                "FortiOS",
            ]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Matched : Yes", result.output)
        self.assertIn("Catalog Product : FortiGate", result.output)
        self.assertIn("Affected Assets : 2", result.output)
        self.assertIn("Owner : IT", result.output)
        self.assertIn("Environment : Production", result.output)
        self.assertIn("Critical : Yes", result.output)
        self.assertLess(
            result.output.index("FG200E\n"),
            result.output.index("FG200E-DR"),
        )
        self.assertNotIn("FG200E-Retired", result.output)

    def test_unmatched_output(self):
        result = self.app.test_cli_runner().invoke(
            args=[
                "analyze-impact",
                "--vendor",
                "Unknown",
                "--product",
                "Unknown Product",
            ]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Matched : No", result.output)
        self.assertIn("Catalog Product : None", result.output)
        self.assertIn("Affected Assets : 0", result.output)

    def test_product_option_is_required(self):
        result = self.app.test_cli_runner().invoke(
            args=["analyze-impact", "--vendor", "Fortinet"]
        )

        self.assertEqual(result.exit_code, 2)
        self.assertIn("Missing option '--product'", result.output)

    def test_command_does_not_modify_data(self):
        with self.app.app_context():
            before = (
                db.session.scalar(
                    db.select(db.func.count(CatalogProduct.CatalogProductId))
                ),
                db.session.scalar(
                    db.select(db.func.count(ProductAlias.ProductAliasId))
                ),
                db.session.scalar(
                    db.select(db.func.count(Asset.AssetId))
                ),
            )

        result = self.app.test_cli_runner().invoke(
            args=[
                "analyze-impact",
                "--vendor",
                "Fortinet",
                "--product",
                "FortiOS",
            ]
        )

        with self.app.app_context():
            after = (
                db.session.scalar(
                    db.select(db.func.count(CatalogProduct.CatalogProductId))
                ),
                db.session.scalar(
                    db.select(db.func.count(ProductAlias.ProductAliasId))
                ),
                db.session.scalar(
                    db.select(db.func.count(Asset.AssetId))
                ),
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
