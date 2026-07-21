from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db

DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")


class CatalogProduct(db.Model):
    __tablename__ = "CatalogProducts"
    __table_args__ = (
        db.UniqueConstraint(
            "VendorName",
            "ProductName",
            name="UQ_CatalogProducts_VendorName_ProductName",
        ),
        db.Index("IX_CatalogProducts_VendorName", "VendorName"),
        db.Index("IX_CatalogProducts_ProductName", "ProductName"),
        db.Index("IX_CatalogProducts_Active", "Active"),
    )

    CatalogProductId = db.Column(db.Integer, primary_key=True)
    VendorName = db.Column(db.Unicode(100), nullable=False)
    ProductName = db.Column(db.Unicode(200), nullable=False)
    ProductFamily = db.Column(db.Unicode(100))
    TechnologyCategory = db.Column(db.Unicode(100))
    Description = db.Column(db.UnicodeText)
    Active = db.Column(
        db.Boolean, nullable=False, default=True, server_default=db.text("1")
    )
    CreatedAt = db.Column(
        DATETIME_TYPE, nullable=False, server_default=db.text("SYSUTCDATETIME()")
    )
    UpdatedAt = db.Column(
        DATETIME_TYPE,
        nullable=False,
        server_default=db.text("SYSUTCDATETIME()"),
        onupdate=db.func.sysutcdatetime(),
    )

    aliases = db.relationship(
        "ProductAlias",
        back_populates="catalog_product",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    assets = db.relationship(
        "Asset", back_populates="catalog_product", passive_deletes="all"
    )
