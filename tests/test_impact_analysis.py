import unittest
from unittest.mock import Mock

from app.extensions import db
from app.models.asset import Asset
from app.models.catalog_product import CatalogProduct
from app.models.product_alias import ProductAlias
from app.services.impact_analysis import ImpactAnalysisService

from tests.support import create_test_app


class ImpactAnalysisServiceTests(unittest.TestCase):
    def setUp(self):
        self.app = create_test_app()
        self.context = self.app.app_context()
        self.context.push()

        self.product = CatalogProduct(
            VendorName="Fortinet",
            ProductName="FortiGate",
            Active=True,
        )
        db.session.add(self.product)
        db.session.flush()
        db.session.add(
            ProductAlias(
                CatalogProductId=self.product.CatalogProductId,
                Alias="FortiOS",
                Active=True,
            )
        )
        db.session.commit()
        self.service = ImpactAnalysisService()

    def tearDown(self):
        engine = db.engine
        db.session.remove()
        self.context.pop()
        engine.dispose()

    def _add_asset(
        self,
        name,
        *,
        critical=False,
        status="Active",
        catalog_product_id=None,
        owner="IT",
        environment="Production",
        location="Bangkok",
    ):
        asset = Asset(
            AssetName=name,
            Critical=critical,
            Status=status,
            CatalogProductId=(
                self.product.CatalogProductId
                if catalog_product_id is None
                else catalog_product_id
            ),
            Owner=owner,
            Environment=environment,
            Location=location,
        )
        db.session.add(asset)
        db.session.commit()
        return asset

    def test_matched_assets_are_active_and_sorted(self):
        self._add_asset("ZZ Critical", critical=True)
        self._add_asset(
            "AA Critical",
            critical=True,
            status="ACTIVE",
            environment="DR",
        )
        self._add_asset("BB Standard", critical=False)
        self._add_asset("Retired Critical", critical=True, status="Retired")

        other_product = CatalogProduct(
            VendorName="Other",
            ProductName="Other Product",
            Active=True,
        )
        db.session.add(other_product)
        db.session.commit()
        self._add_asset(
            "Other Product Asset",
            critical=True,
            catalog_product_id=other_product.CatalogProductId,
        )

        result = self.service.analyze("Fortinet", "FortiOS")

        self.assertTrue(result["matched"])
        self.assertEqual(
            result["catalog_product_id"],
            self.product.CatalogProductId,
        )
        self.assertEqual(result["product_name"], "FortiGate")
        self.assertEqual(result["affected_asset_count"], 3)
        self.assertEqual(
            [asset["asset_name"] for asset in result["affected_assets"]],
            ["AA Critical", "ZZ Critical", "BB Standard"],
        )
        self.assertEqual(
            result["affected_assets"][0],
            {
                "asset_name": "AA Critical",
                "owner": "IT",
                "environment": "DR",
                "critical": True,
                "status": "ACTIVE",
                "location": "Bangkok",
            },
        )

    def test_matched_product_without_assets(self):
        result = self.service.analyze("Fortinet", "FortiOS")

        self.assertTrue(result["matched"])
        self.assertEqual(result["affected_asset_count"], 0)
        self.assertEqual(result["affected_assets"], [])

    def test_unmatched_product_returns_empty_result(self):
        self._add_asset("Unrelated Asset", critical=True)

        result = self.service.analyze("Unknown", "Unknown Product")

        self.assertEqual(
            result,
            {
                "matched": False,
                "catalog_product_id": None,
                "product_name": "Unknown Product",
                "affected_asset_count": 0,
                "affected_assets": [],
            },
        )

    def test_product_normalizer_is_called_once(self):
        normalizer = Mock()
        normalizer.normalize.return_value = {
            "matched": False,
            "catalog_product_id": None,
            "vendor_name": "Unknown",
            "product_name": "Unknown Product",
            "match_type": None,
            "matched_alias": None,
            "confidence": 0,
        }

        result = ImpactAnalysisService(normalizer).analyze(
            "Unknown", "Unknown Product"
        )

        normalizer.normalize.assert_called_once_with(
            "Unknown", "Unknown Product"
        )
        self.assertFalse(result["matched"])


if __name__ == "__main__":
    unittest.main()
