import json
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func

from app.extensions import db
from app.models.collection_run import CollectionRun
from app.models.source import Source
from app.models.source_item import SourceItem
from app.models.threat import Threat
from app.models.vendor import Vendor
from app.services.cve_service import CVEPersistenceService
from app.services.canonical_threats import CanonicalThreatService
from app.services.threat_observations import ThreatObservationService

from .base import BaseCollector
from .deduplication import (
    content_hash,
    raw_content_hash,
    source_item_by_content_hash,
    source_item_by_external_id,
)
from .normalizer import NormalizedItem


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def structured_log(logger, level: int, event: str, **fields):
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    logger.log(level, json.dumps(payload, ensure_ascii=False, default=str))


@dataclass
class CollectionResult:
    collection_run_id: int
    fetched: int = 0
    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    status: str = "Running"


def _get_or_create_vendor(vendor_name: str | None):
    if not vendor_name:
        return None
    statement = db.select(Vendor).where(
        func.lower(Vendor.VendorName) == vendor_name.lower()
    )
    vendor = db.session.scalar(statement)
    if vendor is None:
        vendor = Vendor(
            VendorName=vendor_name,
            Category="Demo Data" if vendor_name.startswith("Demo ") else None,
            Enabled=True,
        )
        db.session.add(vendor)
        db.session.flush()
    return vendor


def _earliest(current, candidate):
    if current is None:
        return candidate
    if candidate is None:
        return current
    return min(current, candidate)


def _latest(current, candidate):
    if current is None:
        return candidate
    if candidate is None:
        return current
    return max(current, candidate)


def _threat_has_source(threat_id: int, source_name: str) -> bool:
    statement = (
        db.select(SourceItem.SourceItemId)
        .join(Source, Source.SourceId == SourceItem.SourceId)
        .where(
            SourceItem.ThreatId == threat_id,
            func.lower(Source.SourceName) == source_name.lower(),
        )
        .limit(1)
    )
    return db.session.scalar(statement) is not None


def _apply_all_threat_values(threat: Threat, item: NormalizedItem, vendor):
    threat.Title = item.title
    threat.VendorId = vendor.VendorId if vendor else None
    threat.Source = item.source_name
    threat.Severity = item.severity
    threat.CVE = item.cve_ids[0] if item.cve_ids else None
    threat.CVSS = item.cvss
    threat.KEV = item.kev
    threat.PublishedDate = item.published_date
    threat.ReferenceUrl = item.source_url
    threat.Summary = item.summary
    threat.Recommendation = item.recommendation
    threat.ModifiedDate = item.source_modified_date


def _apply_nvd_threat_values(threat: Threat, item: NormalizedItem, vendor):
    current_source = (threat.Source or "").casefold()
    nvd_is_current = current_source == "nvd"

    if nvd_is_current or not threat.Title:
        threat.Title = item.title
    if vendor is not None and (nvd_is_current or threat.VendorId is None):
        threat.VendorId = vendor.VendorId
    if nvd_is_current or not threat.Source:
        threat.Source = item.source_name
    if item.source_url and (nvd_is_current or not threat.ReferenceUrl):
        threat.ReferenceUrl = item.source_url
    if item.cve_ids and not threat.CVE:
        threat.CVE = item.cve_ids[0]

    if item.cvss is not None and current_source in {"", "cisa kev", "nvd"}:
        threat.CVSS = item.cvss
        if item.severity:
            threat.Severity = item.severity
    elif item.severity and not threat.Severity:
        threat.Severity = item.severity

    if item.summary and current_source in {"", "cisa kev", "nvd"}:
        threat.Summary = item.summary
    if item.recommendation and not threat.Recommendation:
        threat.Recommendation = item.recommendation

    if current_source in {"", "cisa kev", "nvd"}:
        threat.PublishedDate = _earliest(
            threat.PublishedDate, item.published_date
        )
    elif threat.PublishedDate is None:
        threat.PublishedDate = item.published_date

    threat.ModifiedDate = _latest(
        threat.ModifiedDate, item.source_modified_date
    )
    threat.KEV = bool(threat.KEV or item.kev)


def _apply_cisa_threat_values(threat: Threat, item: NormalizedItem, vendor):
    has_nvd_evidence = bool(
        threat.ThreatId and _threat_has_source(threat.ThreatId, "NVD")
    )
    threat.Title = item.title
    if vendor is not None:
        threat.VendorId = vendor.VendorId
    threat.Source = item.source_name
    threat.ReferenceUrl = item.source_url
    if item.cve_ids:
        threat.CVE = item.cve_ids[0]
    if not has_nvd_evidence:
        if item.severity:
            threat.Severity = item.severity
        if item.summary:
            threat.Summary = item.summary
    if item.cvss is not None and threat.CVSS is None:
        threat.CVSS = item.cvss
    if item.recommendation:
        threat.Recommendation = item.recommendation
    threat.PublishedDate = _earliest(threat.PublishedDate, item.published_date)
    threat.ModifiedDate = _latest(
        threat.ModifiedDate, item.source_modified_date
    )
    threat.KEV = bool(threat.KEV or item.kev)


def _apply_threat_values(
    threat: Threat,
    item: NormalizedItem,
    vendor,
    *,
    is_new: bool,
):
    if is_new:
        _apply_all_threat_values(threat, item, vendor)
    elif item.source_name.casefold() == "nvd":
        _apply_nvd_threat_values(threat, item, vendor)
    elif item.source_name.casefold() == "cisa kev":
        _apply_cisa_threat_values(threat, item, vendor)
    else:
        _apply_all_threat_values(threat, item, vendor)


def _vendor_for_item(item: NormalizedItem, threat: Threat | None):
    if (
        item.source_name.casefold() == "nvd"
        and threat is not None
        and threat.VendorId is not None
    ):
        return db.session.get(Vendor, threat.VendorId)
    return _get_or_create_vendor(item.vendor_name)


def _new_source_item(
    source: Source,
    collection_run_id: int,
    item: NormalizedItem,
    hash_value: str,
    status: str,
    threat: Threat | None,
    match_method: str,
):
    now = utcnow()
    return SourceItem(
        SourceId=source.SourceId,
        CollectionRunId=collection_run_id,
        ExternalId=item.external_id,
        CVE=item.cve_ids[0] if item.cve_ids else None,
        ContentHash=hash_value,
        Title=item.title,
        SourceUrl=item.source_url,
        PublishedDate=item.published_date,
        SourceModifiedDate=item.source_modified_date,
        NormalizedMetadata=item.normalized_metadata,
        MatchMethod=match_method,
        RawContent=item.raw_content,
        ProcessingStatus=status,
        FirstSeenAt=now,
        LastSeenAt=now,
        ThreatId=threat.ThreatId if threat else None,
    )


def _update_source_item(
    source_item: SourceItem,
    collection_run_id: int,
    item: NormalizedItem,
    hash_value: str,
    status: str,
    match_method: str,
):
    source_item.CollectionRunId = collection_run_id
    source_item.CVE = item.cve_ids[0] if item.cve_ids else None
    source_item.ContentHash = hash_value
    source_item.Title = item.title
    source_item.SourceUrl = item.source_url
    source_item.PublishedDate = item.published_date
    source_item.SourceModifiedDate = item.source_modified_date
    source_item.NormalizedMetadata = item.normalized_metadata
    source_item.MatchMethod = match_method
    source_item.RawContent = item.raw_content
    source_item.ProcessingStatus = status
    source_item.ErrorMessage = None
    source_item.LastSeenAt = utcnow()


def _process_item(
    source: Source, collection_run_id: int, item: NormalizedItem
) -> str:
    hash_value = content_hash(item)
    existing_external = source_item_by_external_id(
        source.SourceId, item.external_id
    )

    if existing_external is not None:
        if existing_external.ContentHash == hash_value:
            if existing_external.threat is not None:
                CVEPersistenceService.sync_threat(
                    existing_external.threat,
                    item.cve_ids,
                    source=item.source_name,
                )
                ThreatObservationService.record(
                    existing_external.threat,
                    source,
                    item,
                    match_method="ExistingLink",
                    confidence=1.0,
                )
            _update_source_item(
                existing_external,
                collection_run_id,
                item,
                hash_value,
                status="Duplicate",
                match_method="ExistingLink",
            )
            return "skipped"

        threat = existing_external.threat
        canonical_match = None
        if threat is None:
            canonical_match = (
                CanonicalThreatService.from_app_config().find(item)
            )
            threat = canonical_match.threat
        is_new = threat is None
        if threat is None:
            threat = Threat()
            db.session.add(threat)
        vendor = _vendor_for_item(item, threat)
        _apply_threat_values(threat, item, vendor, is_new=is_new)
        db.session.flush()
        CVEPersistenceService.sync_threat(
            threat, item.cve_ids, source=item.source_name
        )
        ThreatObservationService.record(
            threat,
            source,
            item,
            match_method=(
                canonical_match.method
                if canonical_match is not None
                else "ExistingLink"
            ),
            confidence=(
                canonical_match.confidence
                if canonical_match is not None
                else 1.0
            ),
        )
        existing_external.ThreatId = threat.ThreatId
        _update_source_item(
            existing_external,
            collection_run_id,
            item,
            hash_value,
            status="Processed",
            match_method="ExistingLink",
        )
        return "updated"

    duplicate_source_item = source_item_by_content_hash(hash_value)
    if duplicate_source_item is not None:
        CVEPersistenceService.sync_threat(
            duplicate_source_item.threat,
            item.cve_ids,
            source=item.source_name,
        )
        ThreatObservationService.record(
            duplicate_source_item.threat,
            source,
            item,
            match_method="ContentHash",
            confidence=1.0,
        )
        db.session.add(
            _new_source_item(
                source,
                collection_run_id,
                item,
                hash_value,
                status="Duplicate",
                threat=duplicate_source_item.threat,
                match_method="ContentHash",
            )
        )
        return "skipped"

    canonical_match = CanonicalThreatService.from_app_config().find(item)
    duplicate_threat = canonical_match.threat
    if duplicate_threat is not None:
        vendor = _vendor_for_item(item, duplicate_threat)
        _apply_threat_values(
            duplicate_threat, item, vendor, is_new=False
        )
        db.session.flush()
        CVEPersistenceService.sync_threat(
            duplicate_threat, item.cve_ids, source=item.source_name
        )
        ThreatObservationService.record(
            duplicate_threat,
            source,
            item,
            match_method=canonical_match.method,
            confidence=canonical_match.confidence,
        )
        db.session.add(
            _new_source_item(
                source,
                collection_run_id,
                item,
                hash_value,
                status="Processed",
                threat=duplicate_threat,
                match_method=canonical_match.method,
            )
        )
        return "updated"

    vendor = _get_or_create_vendor(item.vendor_name)
    threat = Threat()
    _apply_threat_values(threat, item, vendor, is_new=True)
    db.session.add(threat)
    db.session.flush()
    CVEPersistenceService.sync_threat(
        threat, item.cve_ids, source=item.source_name
    )
    ThreatObservationService.record(
        threat,
        source,
        item,
        match_method="Created",
        confidence=1.0,
    )
    db.session.add(
        _new_source_item(
            source,
            collection_run_id,
            item,
            hash_value,
            status="Processed",
            threat=threat,
            match_method="Created",
        )
    )
    return "created"


def _serialize_raw_item(raw_item: Any) -> str:
    return json.dumps(
        raw_item, ensure_ascii=False, sort_keys=True, default=str
    )


def _record_failed_item(
    source_id: int,
    collection_run_id: int,
    raw_item: Any,
    error_message: str,
):
    raw_content = _serialize_raw_item(raw_item)
    external_id = None
    cve = None
    title = None
    if isinstance(raw_item, dict):
        external_id_value = raw_item.get("external_id")
        nested_cve = raw_item.get("cve")
        if isinstance(nested_cve, dict):
            external_id_value = nested_cve.get("id") or external_id_value
            cve_value = str(nested_cve.get("id", "")).strip().upper()
            if cve_value.startswith("CVE-"):
                cve = cve_value[:50]
                title = cve
        if external_id_value:
            candidate = str(external_id_value).strip()[:500]
            existing = source_item_by_external_id(source_id, candidate)
            if existing is None:
                external_id = candidate
        title_value = raw_item.get("title")
        if title_value:
            title = str(title_value).strip()[:500]

    now = utcnow()
    failed_item = SourceItem(
        SourceId=source_id,
        CollectionRunId=collection_run_id,
        ExternalId=external_id,
        CVE=cve,
        ContentHash=raw_content_hash(raw_content),
        Title=title,
        MatchMethod="Failed",
        RawContent=raw_content,
        ProcessingStatus="Failed",
        ErrorMessage=error_message[:2000],
        FirstSeenAt=now,
        LastSeenAt=now,
    )
    db.session.add(failed_item)
    db.session.commit()


def _finish_run(
    collection_run_id: int,
    source_id: int,
    result: CollectionResult,
):
    run = db.session.get(CollectionRun, collection_run_id)
    source = db.session.get(Source, source_id)
    finished_at = utcnow()
    successful_items = result.created + result.updated + result.skipped
    if result.errors and successful_items:
        result.status = "Partial"
    elif result.errors:
        result.status = "Failed"
    else:
        result.status = "Success"

    run.FinishedAt = finished_at
    run.Status = result.status
    run.ItemsFetched = result.fetched
    run.ItemsCreated = result.created
    run.ItemsUpdated = result.updated
    run.ItemsSkipped = result.skipped
    run.ErrorMessage = "\n".join(result.errors)[:4000] if result.errors else None
    source.LastCollectionStatus = result.status
    if result.status == "Success":
        source.LastSuccessfulCollection = finished_at
    db.session.commit()


def run_collector(
    collector: BaseCollector,
    source: Source,
    worker_name: str | None = None,
    logger=None,
) -> CollectionResult:
    logger = logger or logging.getLogger(__name__)
    worker_name = worker_name or socket.gethostname()
    run = CollectionRun(
        SourceId=source.SourceId,
        Status="Running",
        WorkerName=worker_name,
        StartedAt=utcnow(),
    )
    db.session.add(run)
    db.session.commit()
    result = CollectionResult(collection_run_id=run.CollectionRunId)
    source_id = source.SourceId

    structured_log(
        logger,
        logging.INFO,
        "collection_started",
        collection_run_id=result.collection_run_id,
        source_id=source_id,
        source_name=source.SourceName,
        worker_name=worker_name,
    )

    try:
        payload = collector.fetch()
        raw_items = list(collector.parse(payload))
        result.fetched = len(raw_items)
    except Exception as exc:
        db.session.rollback()
        result.errors.append(f"collector fetch/parse failed: {exc}")
        _finish_run(result.collection_run_id, source_id, result)
        structured_log(
            logger,
            logging.ERROR,
            "collection_failed",
            collection_run_id=result.collection_run_id,
            source_id=source_id,
            error_type=type(exc).__name__,
            error=str(exc),
        )
        return result

    for item_number, raw_item in enumerate(raw_items, start=1):
        try:
            normalized = collector.normalize(raw_item)
            outcome = _process_item(
                source, result.collection_run_id, normalized
            )
            db.session.commit()
            setattr(result, outcome, getattr(result, outcome) + 1)
        except Exception as exc:
            db.session.rollback()
            message = f"item {item_number}: {type(exc).__name__}: {exc}"
            result.errors.append(message)
            try:
                _record_failed_item(
                    source_id,
                    result.collection_run_id,
                    raw_item,
                    message,
                )
            except Exception:
                db.session.rollback()
                structured_log(
                    logger,
                    logging.ERROR,
                    "collection_failed_item_record_error",
                    collection_run_id=result.collection_run_id,
                    source_id=source_id,
                    item_number=item_number,
                    error=message,
                )
            structured_log(
                logger,
                logging.WARNING,
                "collection_item_failed",
                collection_run_id=result.collection_run_id,
                source_id=source_id,
                item_number=item_number,
                error=message,
            )

    _finish_run(result.collection_run_id, source_id, result)
    structured_log(
        logger,
        logging.INFO if result.status == "Success" else logging.WARNING,
        "collection_finished",
        collection_run_id=result.collection_run_id,
        source_id=source_id,
        status=result.status,
        fetched=result.fetched,
        created=result.created,
        updated=result.updated,
        skipped=result.skipped,
        errors=len(result.errors),
    )
    return result
