from app.extensions import db
from app.models.catalog_product import CatalogProduct


class CatalogProductRepository:
    """Read-only catalog access used by in-memory product normalization."""

    @staticmethod
    def list_active():
        return db.session.execute(
            db.select(CatalogProduct)
            .where(CatalogProduct.Active == True)
            .order_by(CatalogProduct.CatalogProductId.asc())
        ).scalars().all()
