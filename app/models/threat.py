from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db

DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")


class Threat(db.Model):
    __tablename__ = "Threats"
    __table_args__ = (
        db.CheckConstraint(
            "CVSS IS NULL OR CVSS BETWEEN 0.0 AND 10.0",
            name="CK_Threats_CVSS",
        ),
    )

    ThreatId = db.Column(db.Integer, primary_key=True)
    Title = db.Column(db.Unicode(255), nullable=False)
    VendorId = db.Column(db.Integer, db.ForeignKey("Vendors.VendorId"))
    Source = db.Column(db.Unicode(100))
    Severity = db.Column(db.Unicode(20))
    CVE = db.Column(db.Unicode(50))
    CVSS = db.Column(db.Numeric(4, 1))
    KEV = db.Column(db.Boolean, nullable=False, server_default=db.text("0"))
    PublishedDate = db.Column(DATETIME_TYPE)
    ReferenceUrl = db.Column(db.Unicode(1000))
    Summary = db.Column(db.UnicodeText)
    Recommendation = db.Column(db.UnicodeText)
    CreatedAt = db.Column(
        DATETIME_TYPE, nullable=False, server_default=db.text("SYSUTCDATETIME()")
    )

    vendor = db.relationship("Vendor")
