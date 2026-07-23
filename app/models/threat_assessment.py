from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db

DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")


class ThreatAssessment(db.Model):
    __tablename__ = "ThreatAssessments"
    __table_args__ = (
        db.UniqueConstraint(
            "ThreatId", "AssetId", name="UQ_ThreatAssessments_ThreatId_AssetId"
        ),
        db.Index("IX_ThreatAssessments_Status_Action", "ImpactStatus", "RecommendationType"),
    )

    ThreatAssessmentId = db.Column(db.Integer, primary_key=True)
    ThreatId = db.Column(
        db.Integer, db.ForeignKey("Threats.ThreatId", ondelete="CASCADE"), nullable=False
    )
    AssetId = db.Column(
        db.Integer, db.ForeignKey("Assets.AssetId", ondelete="CASCADE"), nullable=False
    )
    ImpactStatus = db.Column(db.Unicode(30), nullable=False)
    MatchReason = db.Column(db.UnicodeText, nullable=False)
    RecommendationType = db.Column(db.Unicode(40), nullable=False)
    RecommendationReason = db.Column(db.UnicodeText, nullable=False)
    Reviewed = db.Column(db.Boolean, nullable=False, server_default=db.text("0"))
    UpdatedAt = db.Column(
        DATETIME_TYPE, nullable=False, server_default=db.text("SYSUTCDATETIME()")
    )

    threat = db.relationship("Threat", back_populates="assessments")
    asset = db.relationship("Asset", back_populates="threat_assessments")
