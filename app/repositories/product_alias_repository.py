from app.extensions import db
from app.models.product_alias import ProductAlias


class ProductAliasRepository:
    """Read-only alias access used by in-memory product normalization."""

    @staticmethod
    def list_active():
        return db.session.execute(
            db.select(ProductAlias)
            .where(ProductAlias.Active == True)
            .order_by(
                ProductAlias.CatalogProductId.asc(),
                ProductAlias.ProductAliasId.asc(),
            )
        ).scalars().all()
