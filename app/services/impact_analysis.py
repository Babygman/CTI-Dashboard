from collections import defaultdict

from app.repositories import AssetRepository
from .product_normalizer import ProductNormalizer


class ImpactAnalysisService:
    """Resolve a product and return active Assets linked to it."""

    def __init__(self, product_normalizer=None, asset_repository=None):
        self.product_normalizer = product_normalizer or ProductNormalizer()
        self.asset_repository = asset_repository or AssetRepository()
        self._preloaded_assets = None

    def preload(self):
        """Load normalization data and active assets once for a dashboard batch."""
        self.product_normalizer.preload()
        self._preloaded_assets = self._load_asset_index()
        return self

    def analyze(self, vendor_name, product_name):
        normalization = self.product_normalizer.normalize(
            vendor_name, product_name
        )
        return self.analyze_normalized(normalization)

    def analyze_normalized(self, normalization):
        """Build impact results from an existing normalization result."""
        if not normalization["matched"]:
            return {
                "matched": False,
                "catalog_product_id": None,
                "product_name": normalization["product_name"],
                "affected_asset_count": 0,
                "affected_assets": [],
            }

        # A preloaded dashboard batch performs this lookup entirely in memory.
        assets_by_product = (
            self._preloaded_assets
            if self._preloaded_assets is not None
            else self._load_asset_index()
        )
        asset_rows = assets_by_product.get(
            normalization["catalog_product_id"], ()
        )

        affected_assets = [
            {
                "asset_name": row.AssetName,
                "owner": row.Owner,
                "environment": row.Environment,
                "critical": bool(row.Critical),
                "status": row.Status,
                "location": row.Location,
            }
            for row in asset_rows
        ]
        return {
            "matched": True,
            "catalog_product_id": normalization["catalog_product_id"],
            "product_name": normalization["product_name"],
            "affected_asset_count": len(affected_assets),
            "affected_assets": affected_assets,
        }

    def _load_asset_index(self):
        assets_by_product = defaultdict(list)
        for row in self.asset_repository.list_active():
            assets_by_product[row.CatalogProductId].append(row)
        return dict(assets_by_product)
