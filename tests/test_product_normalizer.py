import unittest

from sqlalchemy import event

from app.extensions import db
from app.models.catalog_product import CatalogProduct
from app.models.product_alias import ProductAlias
from app.services.product_normalizer import ProductNormalizer

from tests.support import create_test_app


class ProductNormalizerTests(unittest.TestCase):
    def setUp(self):
        self.app = create_test_app()
        self.context = self.app.app_context()
        self.context.push()
        self.fortigate = self._add_product(
            "Fortinet", "FortiGate", aliases=["FortiOS"]
        )
        self.normalizer = ProductNormalizer()

    def tearDown(self):
        engine = db.engine
        db.session.remove()
        self.context.pop()
        engine.dispose()

    @staticmethod
    def _add_product(vendor, product, aliases=(), active=True):
        catalog_product = CatalogProduct(
            VendorName=vendor,
            ProductName=product,
            Active=active,
        )
        db.session.add(catalog_product)
        db.session.flush()
        for alias in aliases:
            db.session.add(
                ProductAlias(
                    CatalogProductId=catalog_product.CatalogProductId,
                    Alias=alias,
                    Active=True,
                )
            )
        db.session.commit()
        return catalog_product

    def test_vendor_and_exact_alias(self):
        result = self.normalizer.normalize("Fortinet", "FortiOS")

        self.assertTrue(result["matched"])
        self.assertEqual(
            result["catalog_product_id"],
            self.fortigate.CatalogProductId,
        )
        self.assertEqual(result["match_type"], "Vendor + Exact Alias")
        self.assertEqual(result["matched_alias"], "FortiOS")
        self.assertEqual(result["confidence"], 100)

    def test_exact_alias_without_vendor(self):
        result = self.normalizer.normalize("", "FortiOS")

        self.assertTrue(result["matched"])
        self.assertEqual(result["match_type"], "Exact Alias")
        self.assertEqual(result["confidence"], 95)

    def test_vendor_and_product_name(self):
        result = self.normalizer.normalize("Fortinet", "FortiGate")

        self.assertTrue(result["matched"])
        self.assertEqual(result["match_type"], "Vendor + ProductName")
        self.assertIsNone(result["matched_alias"])
        self.assertEqual(result["confidence"], 100)

    def test_exact_product_name_without_vendor(self):
        result = self.normalizer.normalize(None, "FortiGate")

        self.assertTrue(result["matched"])
        self.assertEqual(result["match_type"], "Exact ProductName")
        self.assertEqual(result["confidence"], 95)

    def test_case_insensitive_fallback(self):
        result = self.normalizer.normalize("fortinet", "fortios")

        self.assertTrue(result["matched"])
        self.assertEqual(
            result["match_type"],
            "Case-insensitive Vendor + Alias",
        )
        self.assertEqual(result["matched_alias"], "FortiOS")
        self.assertEqual(result["confidence"], 90)

    def test_alias_precedes_canonical_product_name(self):
        canonical_gateway = self._add_product("Microsoft", "Gateway")

        result = self.normalizer.normalize("Microsoft", "FortiOS")
        self.assertEqual(
            result["catalog_product_id"],
            self.fortigate.CatalogProductId,
        )

        db.session.add(
            ProductAlias(
                CatalogProductId=self.fortigate.CatalogProductId,
                Alias="Gateway",
                Active=True,
            )
        )
        db.session.commit()

        result = self.normalizer.normalize("Microsoft", "Gateway")
        self.assertEqual(
            result["catalog_product_id"],
            self.fortigate.CatalogProductId,
        )
        self.assertNotEqual(
            result["catalog_product_id"],
            canonical_gateway.CatalogProductId,
        )
        self.assertEqual(result["match_type"], "Exact Alias")

    def test_ambiguous_alias_is_not_arbitrarily_selected(self):
        second = self._add_product("Other Vendor", "Other Product")
        db.session.add(
            ProductAlias(
                CatalogProductId=second.CatalogProductId,
                Alias="FortiOS",
                Active=True,
            )
        )
        db.session.commit()

        result = self.normalizer.normalize("", "FortiOS")

        self.assertFalse(result["matched"])
        self.assertIsNone(result["catalog_product_id"])
        self.assertEqual(result["confidence"], 0)

    def test_inactive_alias_and_product_are_ignored(self):
        inactive_alias = db.session.scalar(
            db.select(ProductAlias).where(ProductAlias.Alias == "FortiOS")
        )
        inactive_alias.Active = False
        inactive_product = self._add_product(
            "Inactive Vendor",
            "Inactive Product",
            aliases=["Inactive Alias"],
            active=False,
        )
        db.session.commit()

        alias_result = self.normalizer.normalize("Fortinet", "FortiOS")
        product_result = self.normalizer.normalize(
            inactive_product.VendorName,
            inactive_product.ProductName,
        )
        inactive_alias_result = self.normalizer.normalize(
            inactive_product.VendorName,
            "Inactive Alias",
        )

        self.assertFalse(alias_result["matched"])
        self.assertFalse(product_result["matched"])
        self.assertFalse(inactive_alias_result["matched"])

    def test_unmatched_and_blank_product_results(self):
        result = self.normalizer.normalize("Unknown", "Unknown Product")
        blank = self.normalizer.normalize(" Unknown ", "   ")

        self.assertEqual(
            set(result),
            {
                "matched",
                "catalog_product_id",
                "vendor_name",
                "product_name",
                "match_type",
                "matched_alias",
                "confidence",
            },
        )
        self.assertFalse(result["matched"])
        self.assertEqual(result["vendor_name"], "Unknown")
        self.assertEqual(result["product_name"], "Unknown Product")
        self.assertFalse(blank["matched"])
        self.assertEqual(blank["vendor_name"], "Unknown")
        self.assertEqual(blank["product_name"], "")

    def test_preloaded_normalization_uses_two_queries_for_many_inputs(self):
        statements = []

        def record_statement(
            connection,
            cursor,
            statement,
            parameters,
            context,
            executemany,
        ):
            statements.append(statement)

        event.listen(
            db.engine,
            "before_cursor_execute",
            record_statement,
        )
        try:
            self.normalizer.preload()
            first = self.normalizer.normalize("Fortinet", "FortiOS")
            second = self.normalizer.normalize("Fortinet", "FortiGate")
            missing = self.normalizer.normalize("Unknown", "Unknown")
        finally:
            event.remove(
                db.engine,
                "before_cursor_execute",
                record_statement,
            )

        self.assertTrue(first["matched"])
        self.assertTrue(second["matched"])
        self.assertFalse(missing["matched"])
        self.assertEqual(len(statements), 2)


if __name__ == "__main__":
    unittest.main()
