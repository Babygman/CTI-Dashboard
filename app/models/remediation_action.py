from datetime import date, datetime

from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db


DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")

ACTION_TYPES = (
    "Patch",
    "Mitigate",
    "Monitor",
    "Investigate",
    "Notify",
    "Other",
)
PRIORITIES = ("Critical", "High", "Medium", "Low")
ACTION_STATUSES = (
    "Open",
    "In Progress",
    "Blocked",
    "Completed",
    "Cancelled",
)
APPROVAL_STATUSES = (
    "Not Required",
    "Pending",
    "Approved",
    "Rejected",
)
OPEN_ACTION_STATUSES = ("Open", "In Progress", "Blocked")


class RemediationAction(db.Model):
    __tablename__ = "RemediationActions"
    __table_args__ = (
        db.CheckConstraint(
            "ActionType IN "
            "('Patch','Mitigate','Monitor','Investigate','Notify','Other')",
            name="CK_RemediationActions_ActionType",
        ),
        db.CheckConstraint(
            "Priority IN ('Critical','High','Medium','Low')",
            name="CK_RemediationActions_Priority",
        ),
        db.CheckConstraint(
            "Status IN "
            "('Open','In Progress','Blocked','Completed','Cancelled')",
            name="CK_RemediationActions_Status",
        ),
        db.CheckConstraint(
            "ApprovalStatus IN "
            "('Not Required','Pending','Approved','Rejected')",
            name="CK_RemediationActions_ApprovalStatus",
        ),
        db.UniqueConstraint(
            "ThreatId",
            "ActionType",
            "Title",
            name="UQ_RemediationActions_ThreatTypeTitle",
        ),
        db.Index("IX_RemediationActions_ThreatId", "ThreatId"),
        db.Index(
            "IX_RemediationActions_Status_DueDate",
            "Status",
            "DueDate",
        ),
        db.Index("IX_RemediationActions_Owner", "Owner"),
    )

    ActionId = db.Column(db.Integer, primary_key=True)
    ThreatId = db.Column(
        db.Integer,
        db.ForeignKey("Threats.ThreatId"),
        nullable=False,
    )
    Title = db.Column(db.Unicode(255), nullable=False)
    Description = db.Column(db.UnicodeText)
    ActionType = db.Column(db.Unicode(20), nullable=False)
    Priority = db.Column(db.Unicode(20), nullable=False)
    Status = db.Column(
        db.Unicode(20),
        nullable=False,
        default="Open",
        server_default="Open",
    )
    Owner = db.Column(db.Unicode(200))
    DueDate = db.Column(db.Date)
    ApprovalStatus = db.Column(
        db.Unicode(20),
        nullable=False,
        default="Not Required",
        server_default="Not Required",
    )
    TicketReference = db.Column(db.Unicode(255))
    Notes = db.Column(db.UnicodeText)
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
    CompletedAt = db.Column(DATETIME_TYPE)

    threat = db.relationship("Threat", back_populates="remediation_actions")
    history = db.relationship(
        "RemediationActionHistory",
        back_populates="action",
        cascade="all, delete-orphan",
        order_by="RemediationActionHistory.ChangedAt",
    )

    @property
    def is_overdue(self):
        return (
            self.DueDate is not None
            and self.DueDate < date.today()
            and self.Status in OPEN_ACTION_STATUSES
        )
