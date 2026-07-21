from sqlalchemy import func

from app.extensions import db
from app.models.asset import Asset

from .product_normalizer import ProductNormalizer


class ImpactAnalysisService:
    """Resolve a product and return active Assets linked to it."""

    def __init__(self, product_normalizer=None):
        self.product_normalizer = product_normalizer or ProductNormalizer()

    def analyze(self, vendor_name, product_name):
        normalization = self.product_normalizer.normalize(
            vendor_name, product_name
        )
        if not normalization["matched"]:
            return {
                "matched": False,
                "catalog_product_id": None,
                "product_name": normalization["product_name"],
                "affected_asset_count": 0,
                "affected_assets": [],
            }

        asset_rows = db.session.execute(
            db.select(
                Asset.AssetName,
                Asset.Owner,
                Asset.Environment,
                Asset.Critical,
                Asset.Status,
                Asset.Location,
            )
            .where(
                Asset.CatalogProductId
                == normalization["catalog_product_id"],
                func.lower(Asset.Status) == "active",
            )
            .order_by(
                Asset.Critical.desc(),
                Asset.AssetName.asc(),
                Asset.AssetId.asc(),
            )
        ).all()

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
