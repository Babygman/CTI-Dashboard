from sqlalchemy.dialects.mssql import DATETIME2

from app.extensions import db

DATETIME_TYPE = db.DateTime().with_variant(DATETIME2(), "mssql")


class Threat(db.Model):
    __tablename__ = "Threats"
    __table_args__ = (
        db.CheckConstraint(
            "CVSS IS NULL OR CVSS BETWEEN 0.0 AND 10.0",
            name="CK_Threats_CVSS",
        ),
    )

    ThreatId = db.Column(db.Integer, primary_key=True)
    Title = db.Column(db.Unicode(255), nullable=False)
    VendorId = db.Column(db.Integer, db.ForeignKey("Vendors.VendorId"))
    Source = db.Column(db.Unicode(100))
    Severity = db.Column(db.Unicode(20))
    CVE = db.Column(db.Unicode(50))
    CVSS = db.Column(db.Numeric(4, 1))
    KEV = db.Column(db.Boolean, nullable=False, server_default=db.text("0"))
    PublishedDate = db.Column(DATETIME_TYPE)
    ReferenceUrl = db.Column(db.Unicode(1000))
    Summary = db.Column(db.UnicodeText)
    Recommendation = db.Column(db.UnicodeText)
    CreatedAt = db.Column(
        DATETIME_TYPE, nullable=False, server_default=db.text("SYSUTCDATETIME()")
    )
    ModifiedDate = db.Column(DATETIME_TYPE)

    vendor = db.relationship("Vendor")
    remediation_actions = db.relationship(
        "RemediationAction",
        back_populates="threat",
        passive_deletes="all",
    )
    cve_links = db.relationship(
        "ThreatCVE",
        back_populates="threat",
        cascade="all, delete-orphan",
        order_by="(ThreatCVE.IsPrimary.desc(), ThreatCVE.CVEId.asc())",
    )
    observations = db.relationship(
        "ThreatObservation",
        back_populates="threat",
        cascade="all, delete-orphan",
        order_by="ThreatObservation.ObservedDate.asc()",
    )

    @property
    def primary_cve(self):
        if self.cve_links:
            return next(
                (link.cve for link in self.cve_links if link.IsPrimary),
                self.cve_links[0].cve,
            )
        return None

    @property
    def primary_cve_code(self):
        primary = self.primary_cve
        return primary.CVECode if primary else self.CVE

    @property
    def additional_cve_count(self):
        return max(len(self.cve_links) - 1, 0)

    @property
    def contributing_source_count(self):
        return len(
            {
                observation.SourceId
                for observation in self.observations
                if observation.SourceId is not None
            }
        )
