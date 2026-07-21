from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db

DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")


class ProductAlias(db.Model):
    __tablename__ = "ProductAliases"
    __table_args__ = (
        db.UniqueConstraint(
            "CatalogProductId",
            "Alias",
            name="UQ_ProductAliases_CatalogProductId_Alias",
        ),
        db.Index("IX_ProductAliases_Alias", "Alias"),
    )

    ProductAliasId = db.Column(db.Integer, primary_key=True)
    CatalogProductId = db.Column(
        db.Integer,
        db.ForeignKey(
            "CatalogProducts.CatalogProductId",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    Alias = db.Column(db.Unicode(200), nullable=False)
    AliasType = db.Column(db.Unicode(50))
    Active = db.Column(
        db.Boolean, nullable=False, default=True, server_default=db.text("1")
    )
    CreatedAt = db.Column(
        DATETIME_TYPE, nullable=False, server_default=db.text("SYSUTCDATETIME()")
    )

    catalog_product = db.relationship("CatalogProduct", back_populates="aliases")
