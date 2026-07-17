from flask import render_template
from sqlalchemy import func

from app.extensions import db
from app.models.threat import Threat
from app.models.vendor import Vendor

from . import dashboard_blueprint


@dashboard_blueprint.route("/")
def dashboard():
    total_threats = db.session.scalar(
        db.select(func.count(Threat.ThreatId))
    ) or 0
    critical_threats = db.session.scalar(
        db.select(func.count(Threat.ThreatId)).where(
            func.lower(Threat.Severity) == "critical"
        )
    ) or 0
    high_threats = db.session.scalar(
        db.select(func.count(Threat.ThreatId)).where(
            func.lower(Threat.Severity) == "high"
        )
    ) or 0
    kev_threats = db.session.scalar(
        db.select(func.count(Threat.ThreatId)).where(Threat.KEV == True)
    ) or 0
    last_update = db.session.scalar(db.select(func.max(Threat.CreatedAt)))

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
        .outerjoin(Vendor, Threat.VendorId == Vendor.VendorId)
        .group_by(Vendor.VendorName)
        .order_by(vendor_count.desc())
    ).all()

    return render_template(
        "dashboard.html",
        total_threats=total_threats,
        critical_threats=critical_threats,
        high_threats=high_threats,
        kev_threats=kev_threats,
        last_update=last_update,
        severity_labels=[severity or "Unspecified" for severity, _ in severity_rows],
        severity_values=[count for _, count in severity_rows],
        vendor_labels=[vendor or "Unassigned" for vendor, _ in vendor_rows],
        vendor_values=[count for _, count in vendor_rows],
    )
