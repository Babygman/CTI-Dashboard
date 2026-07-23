import hashlib
import json

from app.extensions import db
from app.models.source_item import SourceItem
from app.services.canonical_threats import CanonicalThreatService

from .normalizer import NormalizedItem


def content_hash(item: NormalizedItem) -> str:
    canonical = {
        "title": item.title.casefold(),
        "source_url": (item.source_url or "").casefold(),
        "published_date": (
            item.published_date.isoformat() if item.published_date else None
        ),
        "vendor_name": (item.vendor_name or "").casefold(),
        "severity": item.severity,
        "cve_ids": sorted(item.cve_ids),
        "cvss": str(item.cvss) if item.cvss is not None else None,
        "kev": item.kev,
        "summary": item.summary or "",
        "recommendation": item.recommendation or "",
        "product": item.product or "",
        "known_ransomware_campaign_use": (
            item.known_ransomware_campaign_use or ""
        ),
        "due_date": item.due_date.isoformat() if item.due_date else None,
        "notes": item.notes or "",
    }
    if item.source_modified_date is not None:
        canonical["source_modified_date"] = item.source_modified_date.isoformat()
    if item.normalized_metadata is not None:
        canonical["normalized_metadata"] = item.normalized_metadata
    payload = json.dumps(
        canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def raw_content_hash(raw_content: str) -> str:
    return hashlib.sha256(raw_content.encode("utf-8")).hexdigest()


def source_item_by_external_id(source_id: int, external_id: str | None):
    if not external_id:
        return None
    statement = db.select(SourceItem).where(
        SourceItem.SourceId == source_id,
        SourceItem.ExternalId == external_id,
    )
    return db.session.scalar(statement)


def source_item_by_content_hash(hash_value: str):
    statement = (
        db.select(SourceItem)
        .where(
            SourceItem.ContentHash == hash_value,
            SourceItem.ThreatId.is_not(None),
        )
        .order_by(SourceItem.FirstSeenAt.asc(), SourceItem.SourceItemId.asc())
    )
    return db.session.scalars(statement).first()


def threat_by_identity(item: NormalizedItem):
    return CanonicalThreatService.from_app_config().find(item).threat
