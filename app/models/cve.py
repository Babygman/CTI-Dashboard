from datetime import datetime

from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db


DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")


class CVE(db.Model):
    __tablename__ = "CVEs"
    __table_args__ = (
        db.CheckConstraint(
            "CVECode = UPPER(CVECode)",
            name="CK_CVEs_CVECode_Uppercase",
        ),
        db.UniqueConstraint("CVECode", name="UQ_CVEs_CVECode"),
        db.Index("IX_CVEs_CVSSSeverity", "CVSSSeverity"),
        db.Index("IX_CVEs_CVSSScore", "CVSSScore"),
    )

    CVEId = db.Column(db.Integer, primary_key=True)
    CVECode = db.Column(db.Unicode(30), nullable=False)
    Description = db.Column(db.UnicodeText)
    PublishedAt = db.Column(DATETIME_TYPE)
    ModifiedAt = db.Column(DATETIME_TYPE)
    CVSSScore = db.Column(db.Numeric(4, 1))
    CVSSSeverity = db.Column(db.Unicode(20))
    CWE = db.Column(db.Unicode(100))
    CreatedAt = db.Column(
        DATETIME_TYPE,
        nullable=False,
        default=datetime.utcnow,
        server_default=db.text("SYSUTCDATETIME()"),
    )
    UpdatedAt = db.Column(
        DATETIME_TYPE,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=db.text("SYSUTCDATETIME()"),
    )

    threat_links = db.relationship(
        "ThreatCVE",
        back_populates="cve",
        cascade="all, delete-orphan",
    )

