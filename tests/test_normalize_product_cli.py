import unittest

from app.extensions import db
from app.models.catalog_product import CatalogProduct
from app.models.product_alias import ProductAlias

from tests.support import create_test_app


class NormalizeProductCliTests(unittest.TestCase):
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
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.engine.dispose()

    def test_matched_output(self):
        runner = self.app.test_cli_runner()
        result = runner.invoke(
            args=[
                "normalize-product",
                "--vendor",
                "Fortinet",
                "--product",
                "FortiOS",
            ]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Matched : Yes", result.output)
        self.assertIn("Catalog Product : FortiGate", result.output)
        self.assertIn("Alias : FortiOS", result.output)
        self.assertIn("Confidence : 100", result.output)

    def test_unmatched_output(self):
        runner = self.app.test_cli_runner()
        result = runner.invoke(
            args=[
                "normalize-product",
                "--vendor",
                "Unknown",
                "--product",
                "Unknown Product",
            ]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Matched : No", result.output)
        self.assertIn("Catalog Product : None", result.output)
        self.assertIn("Alias : None", result.output)
        self.assertIn("Confidence : 0", result.output)

    def test_product_option_is_required(self):
        result = self.app.test_cli_runner().invoke(
            args=["normalize-product", "--vendor", "Fortinet"]
        )

        self.assertEqual(result.exit_code, 2)
        self.assertIn("Missing option '--product'", result.output)

    def test_command_does_not_modify_catalog_data(self):
        with self.app.app_context():
            before_products = db.session.scalar(
                db.select(db.func.count(CatalogProduct.CatalogProductId))
            )
            before_aliases = db.session.scalar(
                db.select(db.func.count(ProductAlias.ProductAliasId))
            )

        result = self.app.test_cli_runner().invoke(
            args=[
                "normalize-product",
                "--vendor",
                "Fortinet",
                "--product",
                "FortiOS",
            ]
        )

        with self.app.app_context():
            after_products = db.session.scalar(
                db.select(db.func.count(CatalogProduct.CatalogProductId))
            )
            after_aliases = db.session.scalar(
                db.select(db.func.count(ProductAlias.ProductAliasId))
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(before_products, after_products)
        self.assertEqual(before_aliases, after_aliases)


if __name__ == "__main__":
    unittest.main()