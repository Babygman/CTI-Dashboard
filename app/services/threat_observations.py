import hashlib
from datetime import datetime, timezone
from decimal import Decimal

from app.extensions import db
from app.models.threat_observation import ThreatObservation


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ThreatObservationService:
    @staticmethod
    def record(
        threat,
        source,
        item,
        *,
        match_method,
        confidence,
    ):
        payload_hash = hashlib.sha256(
            item.raw_content.encode("utf-8")
        ).hexdigest()
        observation = None
        if item.external_id:
            observation = db.session.scalar(
                db.select(ThreatObservation).where(
                    ThreatObservation.SourceId == source.SourceId,
                    ThreatObservation.ExternalId == item.external_id,
                )
            )
        if observation is None and not item.external_id:
            observation = db.session.scalar(
                db.select(ThreatObservation).where(
                    ThreatObservation.SourceId == source.SourceId,
                    ThreatObservation.RawPayloadHash == payload_hash,
                )
            )
        if observation is None:
            observation = ThreatObservation(
                SourceId=source.SourceId,
                ExternalId=item.external_id,
                ObservedDate=utcnow(),
                CreatedAt=utcnow(),
            )
            db.session.add(observation)

        observation.ThreatId = threat.ThreatId
        observation.PublishedDate = item.published_date
        observation.Severity = item.severity
        observation.Title = item.title
        observation.Summary = item.summary
        observation.RawPayloadHash = payload_hash
        observation.MatchMethod = match_method
        observation.MatchConfidence = Decimal(str(confidence)).quantize(
            Decimal("0.0001")
        )
        return observation
