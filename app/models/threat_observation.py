from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db


DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")


class ThreatObservation(db.Model):
    __tablename__ = "ThreatObservations"
    __table_args__ = (
        db.CheckConstraint(
            "MatchConfidence BETWEEN 0.0 AND 1.0",
            name="CK_ThreatObservations_MatchConfidence",
        ),
        db.Index(
            "IX_ThreatObservations_ThreatId_PublishedDate",
            "ThreatId",
            "PublishedDate",
        ),
        db.Index(
            "IX_ThreatObservations_SourceId_ExternalId",
            "SourceId",
            "ExternalId",
        ),
        db.Index(
            "IX_ThreatObservations_RawPayloadHash",
            "RawPayloadHash",
        ),
        db.Index(
            "UX_ThreatObservations_SourceId_ExternalId",
            "SourceId",
            "ExternalId",
            unique=True,
            mssql_where=db.text("ExternalId IS NOT NULL"),
            sqlite_where=db.text("ExternalId IS NOT NULL"),
        ),
    )

    ObservationId = db.Column(
        db.BigInteger().with_variant(db.Integer, "sqlite"),
        primary_key=True,
    )
    ThreatId = db.Column(
        db.Integer,
        db.ForeignKey("Threats.ThreatId"),
        nullable=False,
    )
    SourceId = db.Column(
        db.Integer,
        db.ForeignKey("Sources.SourceId"),
    )
    ExternalId = db.Column(db.Unicode(500))
    PublishedDate = db.Column(DATETIME_TYPE)
    ObservedDate = db.Column(
        DATETIME_TYPE,
        nullable=False,
        server_default=db.text("SYSUTCDATETIME()"),
    )
    Severity = db.Column(db.Unicode(20))
    Title = db.Column(db.Unicode(500), nullable=False)
    Summary = db.Column(db.UnicodeText)
    RawPayloadHash = db.Column(db.CHAR(64), nullable=False)
    MatchMethod = db.Column(
        db.Unicode(30),
        nullable=False,
        default="Backfill",
        server_default="Backfill",
    )
    MatchConfidence = db.Column(
        db.Numeric(5, 4),
        nullable=False,
        default=1,
        server_default=db.text("1.0"),
    )
    CreatedAt = db.Column(
        DATETIME_TYPE,
        nullable=False,
        server_default=db.text("SYSUTCDATETIME()"),
    )

    threat = db.relationship("Threat", back_populates="observations")
    source = db.relationship("Source")
