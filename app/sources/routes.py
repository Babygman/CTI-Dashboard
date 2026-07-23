import os
import socket
import uuid
from datetime import timedelta

from flask import (
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from app.collectors.service import run_collector, utcnow
from app.extensions import db
from app.models.source import Source
from app.repositories.collection_lease_repository import (
    CollectionLeaseRepository,
)
from app.services.collection_lease import LeaseHeartbeat

from . import sources_blueprint
from .service import SourceAdministrationService


@sources_blueprint.get("/")
def source_list():
    return render_template(
        "sources.html",
        source_rows=SourceAdministrationService.list_sources(),
    )


@sources_blueprint.get("/<int:source_id>")
def source_detail(source_id):
    source = db.get_or_404(Source, source_id)
    page = max(request.args.get("page", 1, type=int) or 1, 1)
    pagination = SourceAdministrationService.collection_history(
        source_id, page
    )
    return render_template(
        "source_detail.html",
        source_view=SourceAdministrationService.source_detail(source),
        pagination=pagination,
        collection_runs=pagination.items,
    )


@sources_blueprint.post("/<int:source_id>/enable")
def enable_source(source_id):
    source = db.get_or_404(Source, source_id)
    if source.Enabled:
        flash(f"{source.SourceName} is already enabled.", "info")
    else:
        source.Enabled = True
        source.NextRunAt = utcnow()
        db.session.commit()
        flash(f"{source.SourceName} enabled.", "success")
    return redirect(
        url_for("sources.source_detail", source_id=source_id)
    )


@sources_blueprint.post("/<int:source_id>/disable")
def disable_source(source_id):
    source = db.get_or_404(Source, source_id)
    if not source.Enabled:
        flash(f"{source.SourceName} is already disabled.", "info")
    else:
        source.Enabled = False
        db.session.commit()
        flash(f"{source.SourceName} disabled.", "success")
    return redirect(
        url_for("sources.source_detail", source_id=source_id)
    )


@sources_blueprint.post("/<int:source_id>/run")
def run_source(source_id):
    source = db.get_or_404(Source, source_id)
    latest_run = SourceAdministrationService.latest_run(source_id)
    if latest_run is not None and latest_run.Status == "Running":
        flash(
            f"{source.SourceName} already has a running collection.",
            "warning",
        )
        return redirect(
            url_for("sources.source_detail", source_id=source_id)
        )
    if not SourceAdministrationService.collector_available(source):
        flash(
            f"No collector is implemented for source type "
            f"{source.SourceType}.",
            "warning",
        )
        return redirect(
            url_for("sources.source_detail", source_id=source_id)
        )

    lease_owner = (
        f"manual:{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex}"
    )
    lease_timeout = current_app.config.get(
        "CTI_WORKER_LEASE_TIMEOUT_SECONDS", 300
    )
    acquired = CollectionLeaseRepository.acquire(
        source_id,
        lease_owner,
        utcnow(),
        lease_timeout,
        require_due=False,
        require_enabled=False,
    )
    if not acquired:
        flash(
            f"{source.SourceName} is already leased by another worker.",
            "warning",
        )
        return redirect(
            url_for("sources.source_detail", source_id=source_id)
        )

    collector = SourceAdministrationService.create_collector(source)
    heartbeat = LeaseHeartbeat(
        current_app._get_current_object(),
        source_id,
        lease_owner,
        current_app.config.get(
            "CTI_WORKER_HEARTBEAT_INTERVAL_SECONDS", 30
        ),
        lease_timeout,
    )
    heartbeat.start()
    try:
        result = run_collector(
            collector,
            source,
            worker_name="Manual Web Run",
            logger=current_app.logger,
        )
    finally:
        heartbeat.stop()
        CollectionLeaseRepository.release(
            source_id,
            lease_owner,
            utcnow()
            + timedelta(minutes=source.CollectionIntervalMinutes),
        )
    category = "success" if result.status == "Success" else "warning"
    flash(
        f"Collection completed with status {result.status}: "
        f"fetched={result.fetched}, created={result.created}, "
        f"updated={result.updated}, skipped={result.skipped}, "
        f"errors={len(result.errors)}.",
        category,
    )
    return redirect(
        url_for("sources.source_detail", source_id=source_id)
    )
