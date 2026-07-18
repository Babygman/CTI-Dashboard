from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db

DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")

class SourceItem(db.Model):
    __tablename__ = "SourceItems"
    __table_args__ = (
        db.CheckConstraint(
            "ProcessingStatus IN ('Pending', 'Processed', 'Duplicate', 'Failed')",
            name="CK_SourceItems_ProcessingStatus",
        ),
        db.Index("IX_SourceItems_SourceId", "SourceId"),
        db.Index("IX_SourceItems_ContentHash", "ContentHash"),
        db.Index("IX_SourceItems_ProcessingStatus", "ProcessingStatus"),
        db.Index("IX_SourceItems_CollectionRunId", "CollectionRunId"),
        db.Index(
            "IX_SourceItems_CVE",
            "CVE",
            mssql_where=db.text("CVE IS NOT NULL"),
        ),
        db.Index(
            "IX_SourceItems_ThreatId_SourceId",
            "ThreatId",
            "SourceId",
            mssql_include=["FirstSeenAt", "LastSeenAt"],
        ),
        db.Index(
            "UX_SourceItems_SourceId_ExternalId",
            "SourceId",
            "ExternalId",
            unique=True,
            mssql_where=db.text("ExternalId IS NOT NULL"),
        ),
    )

    SourceItemId = db.Column(
        db.BigInteger().with_variant(db.Integer, "sqlite"), primary_key=True
    )
    SourceId = db.Column(
        db.Integer, db.ForeignKey("Sources.SourceId"), nullable=False
    )
    CollectionRunId = db.Column(
        db.BigInteger().with_variant(db.Integer, "sqlite"),
        db.ForeignKey("CollectionRuns.CollectionRunId"),
    )
    ExternalId = db.Column(db.Unicode(500))
    CVE = db.Column(db.Unicode(50))
    ContentHash = db.Column(db.CHAR(64), nullable=False)
    Title = db.Column(db.Unicode(500))
    SourceUrl = db.Column(db.Unicode(1000))
    PublishedDate = db.Column(DATETIME_TYPE)
    SourceModifiedDate = db.Column(DATETIME_TYPE)
    NormalizedMetadata = db.Column(db.UnicodeText)
    MatchMethod = db.Column(db.Unicode(30))
    RawContent = db.Column(db.UnicodeText)
    ProcessingStatus = db.Column(
        db.Unicode(20), nullable=False, default="Pending", server_default="Pending"
    )
    ErrorMessage = db.Column(db.UnicodeText)
    FirstSeenAt = db.Column(
        DATETIME_TYPE, nullable=False, server_default=db.text("SYSUTCDATETIME()")
    )
    LastSeenAt = db.Column(
        DATETIME_TYPE, nullable=False, server_default=db.text("SYSUTCDATETIME()")
    )
    ThreatId = db.Column(db.Integer, db.ForeignKey("Threats.ThreatId"))

    source = db.relationship("Source", back_populates="source_items")
    collection_run = db.relationship("CollectionRun", back_populates="source_items")
    threat = db.relationship("Threat")
