from sqlalchemy import func

from app.extensions import db
from app.models.asset import Asset


class AssetRepository:
    """Read-only asset access used by in-memory impact analysis."""

    @staticmethod
    def list_active():
        return db.session.execute(
            db.select(
                Asset.AssetId,
                Asset.AssetName,
                Asset.Owner,
                Asset.Environment,
                Asset.Critical,
                Asset.Status,
                Asset.Location,
                Asset.CatalogProductId,
            )
            .where(func.lower(Asset.Status) == "active")
            .order_by(
                Asset.Critical.desc(),
                Asset.AssetName.asc(),
                Asset.AssetId.asc(),
            )
        ).all()
