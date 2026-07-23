from sqlalchemy import distinct, func, or_
from sqlalchemy.orm import joinedload, selectinload

from app.extensions import db
from app.models.asset import Asset
from app.models.cve import CVE
from app.models.remediation_action import RemediationAction
from app.models.source import Source
from app.models.source_item import SourceItem
from app.models.threat import Threat
from app.models.threat_cve import ThreatCVE


class CVERepository:
    """Bounded database access for normalized CVE screens and relationships."""

    @staticmethod
    def get(cve_id):
        return db.session.execute(
            db.select(CVE)
            .options(
                selectinload(CVE.threat_links)
                .joinedload(ThreatCVE.threat)
                .joinedload(Threat.vendor)
            )
            .where(CVE.CVEId == cve_id)
        ).scalar_one_or_none()

    @staticmethod
    def list_cves(search="", severity="", minimum=None, maximum=None, limit=500):
        counts = (
            db.select(
                ThreatCVE.CVEId.label("cve_id"),
                func.count(distinct(ThreatCVE.ThreatId)).label(
                    "threat_count"
                ),
            )
            .group_by(ThreatCVE.CVEId)
            .subquery()
        )
        statement = (
            db.select(
                CVE,
                func.coalesce(counts.c.threat_count, 0).label(
                    "threat_count"
                ),
            )
            .options(
                selectinload(CVE.threat_links)
                .joinedload(ThreatCVE.threat)
                .joinedload(Threat.vendor)
            )
            .outerjoin(counts, counts.c.cve_id == CVE.CVEId)
        )
        if search:
            statement = statement.where(CVE.CVECode.ilike(f"%{search}%"))
        if severity:
            statement = statement.where(CVE.CVSSSeverity == severity)
        if minimum is not None:
            statement = statement.where(CVE.CVSSScore >= minimum)
        if maximum is not None:
            statement = statement.where(CVE.CVSSScore <= maximum)
        return db.session.execute(
            statement.order_by(
                CVE.ModifiedAt.desc(),
                CVE.PublishedAt.desc(),
                CVE.CVECode.asc(),
            ).limit(limit)
        ).all()

    @staticmethod
    def related_evidence(cve_id, cve_code):
        return db.session.execute(
            db.select(SourceItem, Source)
            .join(Source, Source.SourceId == SourceItem.SourceId)
            .join(ThreatCVE, ThreatCVE.ThreatId == SourceItem.ThreatId)
            .where(
                ThreatCVE.CVEId == cve_id,
                or_(
                    func.upper(SourceItem.CVE) == cve_code,
                    func.upper(SourceItem.ExternalId) == cve_code,
                    SourceItem.RawContent.ilike(f"%{cve_code}%"),
                ),
            )
            .order_by(SourceItem.FirstSeenAt.asc(), SourceItem.SourceItemId.asc())
        ).all()

    @staticmethod
    def related_actions(threat_ids):
        if not threat_ids:
            return []
        return db.session.execute(
            db.select(RemediationAction)
            .options(joinedload(RemediationAction.threat))
            .where(RemediationAction.ThreatId.in_(threat_ids))
            .order_by(
                RemediationAction.CreatedAt.desc(),
                RemediationAction.ActionId.desc(),
            )
        ).scalars().all()

    @staticmethod
    def all_assets():
        return db.session.execute(
            db.select(Asset).options(joinedload(Asset.catalog_product))
        ).scalars().all()
