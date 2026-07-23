from datetime import datetime

from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db


DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")


class RemediationActionHistory(db.Model):
    __tablename__ = "RemediationActionHistory"
    __table_args__ = (
        db.Index(
            "IX_RemediationActionHistory_ActionId_ChangedAt",
            "ActionId",
            "ChangedAt",
        ),
    )

    HistoryId = db.Column(
        db.BigInteger().with_variant(db.Integer, "sqlite"),
        primary_key=True,
    )
    ActionId = db.Column(
        db.Integer,
        db.ForeignKey(
            "RemediationActions.ActionId",
            ondelete="CASCADE",
        ),
        nullable=False,
    )
    ChangeType = db.Column(db.Unicode(30), nullable=False)
    FieldName = db.Column(db.Unicode(50))
    OldValue = db.Column(db.UnicodeText)
    NewValue = db.Column(db.UnicodeText)
    ChangedAt = db.Column(
        DATETIME_TYPE,
        nullable=False,
        default=datetime.utcnow,
        server_default=db.text("SYSUTCDATETIME()"),
    )

    action = db.relationship(
        "RemediationAction",
        back_populates="history",
    )
