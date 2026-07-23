from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db

DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")


class NewsItem(db.Model):
    __tablename__ = "NewsItems"
    __table_args__ = (
        db.Index("IX_NewsItems_PublishedDate", "PublishedDate"),
        db.Index("IX_NewsItems_Relevance", "IsRelevant"),
    )

    NewsItemId = db.Column(db.Integer, primary_key=True)
    Title = db.Column(db.Unicode(500), nullable=False)
    Source = db.Column(db.Unicode(200), nullable=False)
    ReferenceUrl = db.Column(db.Unicode(1000), nullable=False)
    PublishedDate = db.Column(DATETIME_TYPE)
    Summary = db.Column(db.UnicodeText)
    ThaiSummary = db.Column(db.UnicodeText)
    Vendor = db.Column(db.Unicode(100))
    Product = db.Column(db.Unicode(200))
    CVE = db.Column(db.Unicode(50))
    Severity = db.Column(db.Unicode(20))
    ThreatType = db.Column(db.Unicode(50))
    UserImpact = db.Column(db.UnicodeText)
    ITImpact = db.Column(db.UnicodeText)
    IsRelevant = db.Column(db.Boolean, nullable=True)
    RecommendationType = db.Column(db.Unicode(40))
    RecommendationReason = db.Column(db.UnicodeText)
    CreatedAt = db.Column(
        DATETIME_TYPE, nullable=False, server_default=db.text("SYSUTCDATETIME()")
    )
    UpdatedAt = db.Column(DATETIME_TYPE)

    awareness_records = db.relationship(
        "AwarenessRecord", back_populates="news_item", passive_deletes="all"
    )
