from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db

DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")


class AwarenessRecord(db.Model):
    __tablename__ = "AwarenessRecords"
    __table_args__ = (db.Index("IX_AwarenessRecords_Status", "Status"),)

    AwarenessRecordId = db.Column(db.Integer, primary_key=True)
    ThreatId = db.Column(
        db.Integer, db.ForeignKey("Threats.ThreatId"), nullable=True
    )
    NewsItemId = db.Column(
        db.Integer, db.ForeignKey("NewsItems.NewsItemId"), nullable=True
    )
    Title = db.Column(db.Unicode(500), nullable=False)
    ThaiExplanation = db.Column(db.UnicodeText, nullable=False)
    WhatHappened = db.Column(db.UnicodeText, nullable=False)
    WhoAffected = db.Column(db.UnicodeText, nullable=False)
    MustDo = db.Column(db.UnicodeText, nullable=False)
    MustNotDo = db.Column(db.UnicodeText, nullable=False)
    ReportToIT = db.Column(db.UnicodeText, nullable=False)
    ReferenceUrl = db.Column(db.Unicode(1000))
    Severity = db.Column(db.Unicode(20))
    Status = db.Column(
        db.Unicode(20), nullable=False, default="Draft", server_default=db.text("'Draft'")
    )
    DocumentVersion = db.Column(
        db.Unicode(20), nullable=False, default="1.0", server_default=db.text("'1.0'")
    )
    CreatedAt = db.Column(
        DATETIME_TYPE, nullable=False, server_default=db.text("SYSUTCDATETIME()")
    )
    UpdatedAt = db.Column(DATETIME_TYPE)

    threat = db.relationship("Threat", back_populates="awareness_records")
    news_item = db.relationship("NewsItem", back_populates="awareness_records")
