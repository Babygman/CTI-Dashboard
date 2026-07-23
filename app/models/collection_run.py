from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db

DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")

class CollectionRun(db.Model):
    __tablename__ = "CollectionRuns"
    __table_args__ = (
        db.CheckConstraint(
            "Status IN ('Running', 'Success', 'Partial', 'Failed')",
            name="CK_CollectionRuns_Status",
        ),
        db.CheckConstraint(
            "ItemsFetched >= 0 AND ItemsCreated >= 0 AND ItemsUpdated >= 0 "
            "AND ItemsSkipped >= 0",
            name="CK_CollectionRuns_ItemCounts",
        ),
        db.Index(
            "IX_CollectionRuns_SourceId_StartedAt", "SourceId", "StartedAt"
        ),
        db.Index(
            "UX_CollectionRuns_SourceId_Running",
            "SourceId",
            unique=True,
            mssql_where=db.text("Status = N'Running'"),
            sqlite_where=db.text("Status = 'Running'"),
        ),
    )

    CollectionRunId = db.Column(
        db.BigInteger().with_variant(db.Integer, "sqlite"), primary_key=True
    )
    SourceId = db.Column(
        db.Integer, db.ForeignKey("Sources.SourceId"), nullable=False
    )
    StartedAt = db.Column(
        DATETIME_TYPE, nullable=False, server_default=db.text("SYSUTCDATETIME()")
    )
    FinishedAt = db.Column(DATETIME_TYPE)
    Status = db.Column(
        db.Unicode(20), nullable=False, default="Running", server_default="Running"
    )
    ItemsFetched = db.Column(
        db.Integer, nullable=False, default=0, server_default=db.text("0")
    )
    ItemsCreated = db.Column(
        db.Integer, nullable=False, default=0, server_default=db.text("0")
    )
    ItemsUpdated = db.Column(
        db.Integer, nullable=False, default=0, server_default=db.text("0")
    )
    ItemsSkipped = db.Column(
        db.Integer, nullable=False, default=0, server_default=db.text("0")
    )
    ErrorMessage = db.Column(db.UnicodeText)
    WorkerName = db.Column(db.Unicode(200))

    source = db.relationship("Source", back_populates="collection_runs")
    source_items = db.relationship("SourceItem", back_populates="collection_run")
