from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db

DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")

class Source(db.Model):
    __tablename__ = "Sources"
    __table_args__ = (
        db.CheckConstraint(
            "CollectionIntervalMinutes > 0",
            name="CK_Sources_CollectionIntervalMinutes",
        ),
        db.CheckConstraint("TimeoutSeconds > 0", name="CK_Sources_TimeoutSeconds"),
        db.CheckConstraint(
            "Priority BETWEEN 0 AND 100", name="CK_Sources_Priority"
        ),
        db.Index("IX_Sources_Enabled", "Enabled"),
    )

    SourceId = db.Column(db.Integer, primary_key=True)
    SourceName = db.Column(db.Unicode(200), nullable=False, unique=True)
    SourceType = db.Column(db.Unicode(50), nullable=False)
    BaseUrl = db.Column(db.Unicode(1000))
    FeedUrl = db.Column(db.Unicode(1000))
    Enabled = db.Column(
        db.Boolean, nullable=False, default=True, server_default=db.text("1")
    )
    CollectionIntervalMinutes = db.Column(
        db.Integer, nullable=False, default=60, server_default=db.text("60")
    )
    TimeoutSeconds = db.Column(
        db.Integer, nullable=False, default=30, server_default=db.text("30")
    )
    Priority = db.Column(
        db.SmallInteger, nullable=False, default=50, server_default=db.text("50")
    )
    LastSuccessfulCollection = db.Column(DATETIME_TYPE)
    LastCollectionStatus = db.Column(db.Unicode(20))
    CreatedAt = db.Column(
        DATETIME_TYPE, nullable=False, server_default=db.text("SYSUTCDATETIME()")
    )
    UpdatedAt = db.Column(
        DATETIME_TYPE,
        nullable=False,
        server_default=db.text("SYSUTCDATETIME()"),
        onupdate=db.func.sysutcdatetime(),
    )

    collection_runs = db.relationship(
        "CollectionRun", back_populates="source", order_by="CollectionRun.StartedAt"
    )
    source_items = db.relationship("SourceItem", back_populates="source")
