import re
import unittest
from pathlib import Path

from app.extensions import db
from app.models.catalog_product import CatalogProduct
from app.models.product_alias import ProductAlias
from app.services.product_normalizer import ProductNormalizer
from tests.support import create_test_app


SEED_PATH = (
    Path(__file__).resolve().parents[1]
    / "database"
    / "seed_catalog_products.sql"
)
PRODUCT_PATTERN = re.compile(
    r"\(N'([^']*)', N'([^']*)', N'([^']*)', "
    r"N'([^']*)', N'([^']*)'\)"
)
ALIAS_PATTERN = re.compile(
    r"\(N'([^']*)', N'([^']*)', N'([^']*)', "
    r"N'([^']*)'\)"
)


def _seed_sql():
    return SEED_PATH.read_text(encoding="utf-8-sig")


def _product_rows(sql):
    section = sql.split("INSERT INTO @SeedProducts", 1)[1]
    section = section.split("IF EXISTS", 1)[0]
    return PRODUCT_PATTERN.findall(section)


def _alias_rows(sql):
    section = sql.split("INSERT INTO @SeedAliases", 1)[1]
    section = section.split("IF EXISTS", 1)[0]
    return ALIAS_PATTERN.findall(section)


class CatalogSeedSqlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = _seed_sql()
        cls.products = _product_rows(cls.sql)
        cls.aliases = _alias_rows(cls.sql)

    def test_seed_has_focused_product_count(self):
        self.assertEqual(len(self.products), 38)
        self.assertGreaterEqual(len(self.products), 30)
        self.assertLessEqual(len(self.products), 50)

    def test_no_duplicate_vendor_product_pairs(self):
        keys = [
            (vendor.strip().casefold(), product.strip().casefold())
            for vendor, product, _, _, _ in self.products
        ]
        self.assertEqual(len(keys), len(set(keys)))

    def test_seed_sql_is_idempotent_and_transactional(self):
        upper_sql = self.sql.upper()
        for expected in (
            "SET XACT_ABORT ON",
            "BEGIN TRANSACTION",
            "COMMIT TRANSACTION",
            "ROLLBACK TRANSACTION",
            "BEGIN TRY",
            "BEGIN CATCH",
            "WHERE NOT EXISTS",
            "WITH (UPDLOCK, HOLDLOCK)",
        ):
            self.assertIn(expected, upper_sql)
        self.assertNotIn("MERGE ", upper_sql)
        self.assertNotIn("DELETE FROM DBO.CATALOGPRODUCTS", upper_sql)

    def test_inactive_existing_products_are_reactivated(self):
        self.assertIn("WHEN cp.Active = 0 THEN N'Reactivated'", self.sql)
        self.assertIn("Active = 1", self.sql)
        self.assertIn("WHERE cp.Active = 0", self.sql)

    def test_existing_product_metadata_is_updated(self):
        update_section = self.sql.split("UPDATE cp", 1)[1]
        update_section = update_section.split(
            "INSERT INTO dbo.CatalogProducts", 1
        )[0]
        for assignment in (
            "ProductFamily = seed.ProductFamily",
            "TechnologyCategory = seed.TechnologyCategory",
            "Description = seed.Description",
            "UpdatedAt = SYSUTCDATETIME()",
        ):
            self.assertIn(assignment, update_section)

    def test_existing_fortinet_fortigate_product_is_preserved(self):
        fortigate = [
            row
            for row in self.products
            if row[0].casefold() == "fortinet"
            and row[1].casefold() == "fortigate"
        ]
        self.assertEqual(len(fortigate), 1)
        self.assertIn(
            "INNER JOIN @SeedProducts AS seed", self.sql
        )
        self.assertNotIn(
            "DELETE FROM dbo.CatalogProducts", self.sql
        )

    def test_aliases_are_unique_and_target_seed_products(self):
        product_keys = {
            (vendor.casefold(), product.casefold())
            for vendor, product, _, _, _ in self.products
        }
        alias_values = []
        for vendor, product, alias, _ in self.aliases:
            self.assertIn(
                (vendor.casefold(), product.casefold()), product_keys
            )
            alias_values.append(alias.strip().casefold())
        self.assertEqual(len(alias_values), len(set(alias_values)))

    def test_alias_safety_checks_prevent_normalizer_ambiguity(self):
        self.assertIn(
            "Existing ProductAliases contains ambiguous "
            "case-insensitive matches",
            self.sql,
        )
        self.assertIn(
            "An existing alias maps to a different product",
            self.sql,
        )
        self.assertIn(
            "A seed alias conflicts with a different active "
            "canonical product name",
            self.sql,
        )

    def test_seed_references_actual_catalog_schema(self):
        self.assertNotIn("VendorId", self.sql)
        self.assertNotIn("CatalogProducts.Enabled", self.sql)
        for column in (
            "CatalogProductId",
            "VendorName",
            "ProductName",
            "ProductFamily",
            "TechnologyCategory",
            "Description",
            "Active",
            "UpdatedAt",
        ):
            self.assertIn(column, self.sql)
    def test_summary_includes_all_required_outcomes(self):
        for outcome in (
            "AS Inserted",
            "AS Updated",
            "AS Reactivated",
            "AS Unchanged",
        ):
            self.assertIn(outcome, self.sql)


class CatalogSeedAliasResolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sql = _seed_sql()
        cls.products = _product_rows(sql)
        cls.aliases = _alias_rows(sql)

    def setUp(self):
        self.app = create_test_app()
        self.context = self.app.app_context()
        self.context.push()
        products = {}
        for vendor, product, family, category, description in self.products:
            catalog_product = CatalogProduct(
                VendorName=vendor,
                ProductName=product,
                ProductFamily=family,
                TechnologyCategory=category,
                Description=description,
                Active=True,
            )
            db.session.add(catalog_product)
            db.session.flush()
            products[(vendor.casefold(), product.casefold())] = (
                catalog_product
            )
        for vendor, product, alias, alias_type in self.aliases:
            catalog_product = products[
                (vendor.casefold(), product.casefold())
            ]
            db.session.add(
                ProductAlias(
                    CatalogProductId=(
                        catalog_product.CatalogProductId
                    ),
                    Alias=alias,
                    AliasType=alias_type,
                    Active=True,
                )
            )
        db.session.commit()
        self.normalizer = ProductNormalizer()

    def tearDown(self):
        engine = db.engine
        db.session.remove()
        self.context.pop()
        engine.dispose()

    def test_common_aliases_resolve_expected_products(self):
        cases = (
            ("Microsoft", "Windows Server 2022", "Windows Server"),
            ("Microsoft", "Microsoft Edge", "Edge"),
            ("Google", "Google Chrome", "Chrome"),
            ("Broadcom VMware", "VMware ESXi", "ESXi"),
            (
                "Veeam",
                "Veeam Backup & Replication",
                "Backup & Replication",
            ),
            ("Fortinet", "Fortigate", "FortiGate"),
            ("Cisco", "Cisco IOS XE", "IOS XE"),
            ("Apache", "Apache HTTP Server", "HTTP Server"),
        )
        for vendor, alias, expected_product in cases:
            with self.subTest(alias=alias):
                result = self.normalizer.normalize(vendor, alias)
                self.assertTrue(result["matched"])
                self.assertEqual(
                    result["product_name"], expected_product
                )

    def test_fortios_resolves_to_fortigate_alias(self):
        result = self.normalizer.normalize("Fortinet", "FortiOS")

        self.assertTrue(result["matched"])
        self.assertEqual(result["product_name"], "FortiGate")
        self.assertEqual(result["matched_alias"], "FortiOS")


if __name__ == "__main__":
    unittest.main()





