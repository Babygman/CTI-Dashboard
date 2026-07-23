from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db

DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")


class Asset(db.Model):
    __tablename__ = "Assets"
    __table_args__ = (
        db.Index("IX_Assets_CatalogProductId", "CatalogProductId"),
    )

    AssetId = db.Column(db.Integer, primary_key=True)
    AssetName = db.Column(db.Unicode(200), nullable=False)
    Vendor = db.Column(db.Unicode(100))
    Product = db.Column(db.Unicode(200))
    Version = db.Column(db.Unicode(100))
    AssetType = db.Column(db.Unicode(100))
    Quantity = db.Column(
        db.Integer, nullable=False, default=1, server_default=db.text("1")
    )
    Department = db.Column(db.Unicode(200))
    Critical = db.Column(
        db.Boolean, nullable=False, default=False, server_default=db.text("0")
    )
    Environment = db.Column(db.Unicode(100))
    Owner = db.Column(db.Unicode(200))
    Location = db.Column(db.Unicode(255))
    Status = db.Column(
        db.Unicode(50),
        nullable=False,
        default="Active",
        server_default=db.text("'Active'"),
    )
    Notes = db.Column(db.UnicodeText)
    CreatedAt = db.Column(
        DATETIME_TYPE, nullable=False, server_default=db.text("SYSUTCDATETIME()")
    )
    UpdatedAt = db.Column(
        DATETIME_TYPE,
        nullable=False,
        server_default=db.text("SYSUTCDATETIME()"),
        onupdate=db.func.sysutcdatetime(),
    )
    CatalogProductId = db.Column(
        db.Integer,
        db.ForeignKey("CatalogProducts.CatalogProductId"),
    )

    catalog_product = db.relationship("CatalogProduct", back_populates="assets")
    threat_assessments = db.relationship(
        "ThreatAssessment", back_populates="asset", cascade="all, delete-orphan"
    )
