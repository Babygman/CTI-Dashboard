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

from .base import BaseCollector
from .deduplication import (
    content_hash,
    raw_content_hash,
    source_item_by_content_hash,
    source_item_by_external_id,
    threat_by_identity,
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


def _apply_threat_values(threat: Threat, item: NormalizedItem, vendor):
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


def _new_source_item(
    source: Source,
    item: NormalizedItem,
    hash_value: str,
    status: str,
    threat: Threat | None,
):
    now = utcnow()
    return SourceItem(
        SourceId=source.SourceId,
        ExternalId=item.external_id,
        ContentHash=hash_value,
        Title=item.title,
        SourceUrl=item.source_url,
        PublishedDate=item.published_date,
        RawContent=item.raw_content,
        ProcessingStatus=status,
        FirstSeenAt=now,
        LastSeenAt=now,
        ThreatId=threat.ThreatId if threat else None,
    )


def _update_source_item(
    source_item: SourceItem,
    item: NormalizedItem,
    hash_value: str,
    status: str,
):
    source_item.ContentHash = hash_value
    source_item.Title = item.title
    source_item.SourceUrl = item.source_url
    source_item.PublishedDate = item.published_date
    source_item.RawContent = item.raw_content
    source_item.ProcessingStatus = status
    source_item.ErrorMessage = None
    source_item.LastSeenAt = utcnow()


def _process_item(source: Source, item: NormalizedItem) -> str:
    hash_value = content_hash(item)
    existing_external = source_item_by_external_id(
        source.SourceId, item.external_id
    )

    if existing_external is not None:
        if existing_external.ContentHash == hash_value:
            _update_source_item(
                existing_external, item, hash_value, status="Duplicate"
            )
            return "skipped"

        vendor = _get_or_create_vendor(item.vendor_name)
        threat = existing_external.threat
        if threat is None:
            threat = threat_by_identity(item)
        if threat is None:
            threat = Threat()
            db.session.add(threat)
        _apply_threat_values(threat, item, vendor)
        db.session.flush()
        existing_external.ThreatId = threat.ThreatId
        _update_source_item(existing_external, item, hash_value, status="Processed")
        return "updated"

    duplicate_source_item = source_item_by_content_hash(hash_value)
    if duplicate_source_item is not None:
        db.session.add(
            _new_source_item(
                source,
                item,
                hash_value,
                status="Duplicate",
                threat=duplicate_source_item.threat,
            )
        )
        return "skipped"

    duplicate_threat = threat_by_identity(item)
    if duplicate_threat is not None:
        vendor = _get_or_create_vendor(item.vendor_name)
        _apply_threat_values(duplicate_threat, item, vendor)
        db.session.flush()
        db.session.add(
            _new_source_item(
                source,
                item,
                hash_value,
                status="Processed",
                threat=duplicate_threat,
            )
        )
        return "updated"

    vendor = _get_or_create_vendor(item.vendor_name)
    threat = Threat()
    _apply_threat_values(threat, item, vendor)
    db.session.add(threat)
    db.session.flush()
    db.session.add(
        _new_source_item(
            source, item, hash_value, status="Processed", threat=threat
        )
    )
    return "created"


def _serialize_raw_item(raw_item: Any) -> str:
    return json.dumps(
        raw_item, ensure_ascii=False, sort_keys=True, default=str
    )


def _record_failed_item(source_id: int, raw_item: Any, error_message: str):
    raw_content = _serialize_raw_item(raw_item)
    external_id = None
    title = None
    if isinstance(raw_item, dict):
        external_id_value = raw_item.get("external_id")
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
        ExternalId=external_id,
        ContentHash=raw_content_hash(raw_content),
        Title=title,
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
            outcome = _process_item(source, normalized)
            db.session.commit()
            setattr(result, outcome, getattr(result, outcome) + 1)
        except Exception as exc:
            db.session.rollback()
            message = f"item {item_number}: {type(exc).__name__}: {exc}"
            result.errors.append(message)
            try:
                _record_failed_item(source_id, raw_item, message)
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
