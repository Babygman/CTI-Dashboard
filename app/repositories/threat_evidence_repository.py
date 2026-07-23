from sqlalchemy.orm import joinedload, selectinload

from app.extensions import db
from app.models.collection_run import CollectionRun
from app.models.source import Source
from app.models.source_item import SourceItem
from app.models.threat import Threat
from app.models.threat_cve import ThreatCVE


class ThreatEvidenceRepository:
    """Read a threat and all of its persisted source evidence."""

    @staticmethod
    def get_threat(threat_id):
        return db.session.scalar(
            db.select(Threat)
            .options(
                joinedload(Threat.vendor),
                selectinload(Threat.cve_links).joinedload(ThreatCVE.cve),
            )
            .where(Threat.ThreatId == threat_id)
        )

    @staticmethod
    def list_evidence(threat_id):
        return db.session.execute(
            db.select(SourceItem, Source, CollectionRun)
            .join(Source, Source.SourceId == SourceItem.SourceId)
            .outerjoin(
                CollectionRun,
                CollectionRun.CollectionRunId
                == SourceItem.CollectionRunId,
            )
            .where(SourceItem.ThreatId == threat_id)
            .order_by(
                SourceItem.FirstSeenAt.asc(),
                Source.SourceName.asc(),
                SourceItem.SourceItemId.asc(),
            )
        ).all()
