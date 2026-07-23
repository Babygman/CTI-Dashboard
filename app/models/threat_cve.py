from datetime import datetime

from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db


DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")


class ThreatCVE(db.Model):
    __tablename__ = "ThreatCVEs"
    __table_args__ = (
        db.Index("IX_ThreatCVEs_CVEId", "CVEId"),
        db.Index(
            "UX_ThreatCVEs_OnePrimary",
            "ThreatId",
            unique=True,
            mssql_where=db.text("IsPrimary = 1"),
            sqlite_where=db.text("IsPrimary = 1"),
        ),
    )

    ThreatId = db.Column(
        db.Integer,
        db.ForeignKey("Threats.ThreatId", ondelete="CASCADE"),
        primary_key=True,
    )
    CVEId = db.Column(
        db.Integer,
        db.ForeignKey("CVEs.CVEId", ondelete="CASCADE"),
        primary_key=True,
    )
    IsPrimary = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default=db.text("0"),
    )
    Source = db.Column(db.Unicode(100))
    FirstSeenAt = db.Column(
        DATETIME_TYPE,
        nullable=False,
        default=datetime.utcnow,
        server_default=db.text("SYSUTCDATETIME()"),
    )
    LastSeenAt = db.Column(
        DATETIME_TYPE,
        nullable=False,
        default=datetime.utcnow,
        server_default=db.text("SYSUTCDATETIME()"),
    )

    threat = db.relationship("Threat", back_populates="cve_links")
    cve = db.relationship("CVE", back_populates="threat_links")
