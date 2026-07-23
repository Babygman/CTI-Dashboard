from flask import render_template
from sqlalchemy import case, distinct, func

from app.extensions import db
from app.models.collection_run import CollectionRun
from app.models.source import Source
from app.models.source_item import SourceItem
from app.models.threat import Threat
from app.models.threat_observation import ThreatObservation
from app.models.vendor import Vendor
from app.services.operations_dashboard import OperationsDashboardService
from app.repositories import RemediationActionRepository

from . import dashboard_blueprint


@dashboard_blueprint.route("/")
def dashboard():
    threat_metrics = db.session.execute(
        db.select(
            func.count(Threat.ThreatId),
            func.sum(
                case((func.lower(Threat.Severity) == "critical", 1), else_=0)
            ),
            func.sum(
                case((func.lower(Threat.Severity) == "high", 1), else_=0)
            ),
            func.sum(case((Threat.KEV == True, 1), else_=0)),
            func.max(Threat.CreatedAt),
        )
    ).one()
    total_threats = threat_metrics[0] or 0
    critical_threats = threat_metrics[1] or 0
    high_threats = threat_metrics[2] or 0
    kev_threats = threat_metrics[3] or 0
    last_update = threat_metrics[4]

    source_item_metrics = db.session.execute(
        db.select(
            func.count(SourceItem.SourceItemId),
            func.sum(
                case((func.lower(Source.SourceName) == "cisa kev", 1), else_=0)
            ),
            func.sum(case((func.lower(Source.SourceName) == "nvd", 1), else_=0)),
        )
        .select_from(SourceItem)
        .join(Source, SourceItem.SourceId == Source.SourceId)
    ).one()
    total_source_items = source_item_metrics[0] or 0
    cisa_source_items = source_item_metrics[1] or 0
    nvd_source_items = source_item_metrics[2] or 0

    multi_source_threats_query = (
        db.select(SourceItem.ThreatId)
        .where(SourceItem.ThreatId.is_not(None))
        .group_by(SourceItem.ThreatId)
        .having(func.count(distinct(SourceItem.SourceId)) > 1)
        .subquery()
    )
    multi_source_threats = db.session.scalar(
        db.select(func.count()).select_from(multi_source_threats_query)
    ) or 0
    enabled_sources = db.session.scalar(
        db.select(func.count(Source.SourceId)).where(Source.Enabled == True)
    ) or 0
    contributing_sources = db.session.scalar(
        db.select(func.count(distinct(ThreatObservation.SourceId))).where(
            ThreatObservation.SourceId.is_not(None)
        )
    ) or 0

    latest_run_row = db.session.execute(
        db.select(CollectionRun, Source.SourceName)
        .join(Source, CollectionRun.SourceId == Source.SourceId)
        .order_by(
            CollectionRun.StartedAt.desc(), CollectionRun.CollectionRunId.desc()
        )
        .limit(1)
    ).first()
    latest_run = latest_run_row[0] if latest_run_row else None
    latest_run_source = latest_run_row[1] if latest_run_row else None
    latest_run_errors = (
        len(
            [
                line
                for line in (latest_run.ErrorMessage or "").splitlines()
                if line.strip()
            ]
        )
        if latest_run
        else 0
    )

    severity_count = func.count(Threat.ThreatId)
    severity_rows = db.session.execute(
        db.select(Threat.Severity, severity_count)
        .group_by(Threat.Severity)
        .order_by(severity_count.desc())
    ).all()

    vendor_count = func.count(Threat.ThreatId)
    vendor_rows = db.session.execute(
        db.select(Vendor.VendorName, vendor_count)
        .select_from(Threat)
        .join(Vendor, Threat.VendorId == Vendor.VendorId)
        .group_by(Vendor.VendorName)
        .order_by(vendor_count.desc(), Vendor.VendorName.asc())
        .limit(10)
    ).all()

    operations = OperationsDashboardService().analyze()
    open_remediation_actions = (
        RemediationActionRepository.list_open()
    )

    return render_template(
        "dashboard.html",
        operations=operations,
        total_threats=total_threats,
        critical_threats=critical_threats,
        high_threats=high_threats,
        kev_threats=kev_threats,
        last_update=last_update,
        total_source_items=total_source_items,
        cisa_source_items=cisa_source_items,
        nvd_source_items=nvd_source_items,
        multi_source_threats=multi_source_threats,
        enabled_sources=enabled_sources,
        contributing_sources=contributing_sources,
        latest_run=latest_run,
        latest_run_source=latest_run_source,
        latest_run_errors=latest_run_errors,
        severity_labels=[severity or "Unspecified" for severity, _ in severity_rows],
        severity_values=[count for _, count in severity_rows],
        vendor_labels=[vendor for vendor, _ in vendor_rows],
        vendor_values=[count for _, count in vendor_rows],
        open_remediation_actions=open_remediation_actions,
    )
