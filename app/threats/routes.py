from datetime import datetime
from decimal import Decimal, InvalidOperation

from flask import flash, redirect, render_template, request, url_for
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import selectinload

from app.extensions import db
from app.models.cve import CVE
from app.models.source_item import SourceItem
from app.models.threat import Threat
from app.models.vendor import Vendor
from app.models.threat_cve import ThreatCVE
from app.models.threat_observation import ThreatObservation
from app.services.cve_service import CVEPersistenceService, normalize_cve_code
from app.services.threat_detail import ThreatDetailService

from . import threats_blueprint


SEVERITIES = ("Critical", "High", "Medium", "Low")


def _get_vendors():
    statement = db.select(Vendor).order_by(Vendor.VendorName.asc())
    return db.session.execute(statement).scalars().all()


def _title_exists(title, excluded_threat_id=None):
    statement = db.select(Threat.ThreatId).where(
        func.lower(Threat.Title) == title.lower()
    )
    if excluded_threat_id is not None:
        statement = statement.where(Threat.ThreatId != excluded_threat_id)
    return db.session.scalar(statement) is not None


def _empty_form_data():
    return {
        "title": "",
        "vendor_id": "",
        "source": "",
        "severity": "",
        "cve": "",
        "cvss": "",
        "kev": False,
        "published_date": "",
        "reference_url": "",
        "summary": "",
        "recommendation": "",
    }


def _validate_form():
    form_data = {
        "title": request.form.get("title", "").strip(),
        "vendor_id": request.form.get("vendor_id", "").strip(),
        "source": request.form.get("source", "").strip(),
        "severity": request.form.get("severity", "").strip(),
        "cve": request.form.get("cve", "").strip(),
        "cvss": request.form.get("cvss", "").strip(),
        "kev": "kev" in request.form,
        "published_date": request.form.get("published_date", "").strip(),
        "reference_url": request.form.get("reference_url", "").strip(),
        "summary": request.form.get("summary", "").strip(),
        "recommendation": request.form.get("recommendation", "").strip(),
    }
    errors = {}

    if not form_data["title"]:
        errors["title"] = "Title is required."
    elif len(form_data["title"]) > 255:
        errors["title"] = "Title must be 255 characters or fewer."

    length_limits = {
        "source": (100, "Source"),
        "severity": (20, "Severity"),
        "cve": (50, "CVE"),
        "reference_url": (1000, "Reference URL"),
    }
    for field, (maximum, label) in length_limits.items():
        if len(form_data[field]) > maximum:
            errors[field] = f"{label} must be {maximum} characters or fewer."

    if form_data["severity"] and form_data["severity"] not in SEVERITIES:
        errors["severity"] = "Select a valid severity."

    vendor_id = None
    if form_data["vendor_id"]:
        try:
            vendor_id = int(form_data["vendor_id"])
        except ValueError:
            errors["vendor_id"] = "Select a valid vendor."
        else:
            if db.session.get(Vendor, vendor_id) is None:
                errors["vendor_id"] = "Select a valid vendor."

    cvss = None
    if form_data["cvss"]:
        try:
            cvss = Decimal(form_data["cvss"])
        except InvalidOperation:
            errors["cvss"] = "CVSS must be a number between 0.0 and 10.0."
        else:
            if (
                not cvss.is_finite()
                or cvss < Decimal("0.0")
                or cvss > Decimal("10.0")
            ):
                errors["cvss"] = "CVSS must be between 0.0 and 10.0."

    published_date = None
    if form_data["published_date"]:
        try:
            published_date = datetime.fromisoformat(form_data["published_date"])
        except ValueError:
            errors["published_date"] = "Published Date is invalid."

    values = {
        "Title": form_data["title"],
        "VendorId": vendor_id,
        "Source": form_data["source"] or None,
        "Severity": form_data["severity"] or None,
        "CVE": form_data["cve"] or None,
        "CVSS": cvss,
        "KEV": form_data["kev"],
        "PublishedDate": published_date,
        "ReferenceUrl": form_data["reference_url"] or None,
        "Summary": form_data["summary"] or None,
        "Recommendation": form_data["recommendation"] or None,
    }
    return form_data, values, errors


def _assign_values(threat, values):
    for field, value in values.items():
        setattr(threat, field, value)


@threats_blueprint.route("/threats")
def threat_list():
    query = request.args.get("q", "").strip()
    vendor_id = request.args.get("vendor_id", type=int)
    severity = request.args.get("severity", "").strip()
    if severity not in SEVERITIES:
        severity = ""

    statement = db.select(Threat).options(
        joinedload(Threat.vendor),
        selectinload(Threat.cve_links).joinedload(ThreatCVE.cve),
        selectinload(Threat.observations).joinedload(
            ThreatObservation.source
        ),
    )
    if query:
        pattern = f"%{query}%"
        statement = statement.where(
            or_(
                Threat.Title.ilike(pattern),
                Threat.CVE.ilike(pattern),
                Threat.cve_links.any(
                    ThreatCVE.cve.has(CVE.CVECode.ilike(pattern))
                ),
                Threat.Source.ilike(pattern),
                Threat.Summary.ilike(pattern),
            )
        )
    if vendor_id is not None:
        statement = statement.where(Threat.VendorId == vendor_id)
    if severity:
        statement = statement.where(Threat.Severity == severity)

    statement = statement.order_by(
        Threat.PublishedDate.desc(), Threat.CreatedAt.desc(), Threat.ThreatId.desc()
    )
    threats = db.session.execute(statement).scalars().all()

    return render_template(
        "threats.html",
        threats=threats,
        vendors=_get_vendors(),
        severity_options=SEVERITIES,
        q=query,
        selected_vendor_id=vendor_id,
        selected_severity=severity,
    )


@threats_blueprint.get("/threats/<int:threat_id>")
def threat_detail(threat_id):
    detail = ThreatDetailService().get(threat_id)
    if detail is None:
        return "", 404

    query = request.args.get("return_q", "").strip()
    vendor_id = request.args.get("return_vendor_id", type=int)
    severity = request.args.get("return_severity", "").strip()
    if severity not in SEVERITIES:
        severity = ""
    back_url = url_for(
        "threats.threat_list",
        q=query or None,
        vendor_id=vendor_id,
        severity=severity or None,
    )
    return render_template(
        "threat_detail.html",
        detail=detail,
        back_url=back_url,
    )


@threats_blueprint.route("/threats/add", methods=["GET", "POST"])
def add_threat():
    form_data = _empty_form_data()
    errors = {}

    if request.method == "POST":
        form_data, values, errors = _validate_form()
        if "title" not in errors and _title_exists(form_data["title"]):
            errors["title"] = "A threat with this title already exists."

        if not errors:
            threat = Threat()
            _assign_values(threat, values)
            db.session.add(threat)
            db.session.flush()
            normalized_cve = normalize_cve_code(threat.CVE)
            if normalized_cve:
                CVEPersistenceService.sync_threat(
                    threat, [normalized_cve], source=threat.Source
                )
            db.session.commit()
            flash("Threat added successfully.", "success")
            return redirect(url_for("threats.threat_list"))

    return render_template(
        "threat_form.html",
        page_title="Add Threat",
        form_data=form_data,
        errors=errors,
        vendors=_get_vendors(),
        severity_options=SEVERITIES,
    )


@threats_blueprint.route("/threats/<int:threat_id>/edit", methods=["GET", "POST"])
def edit_threat(threat_id):
    threat = db.get_or_404(Threat, threat_id)
    errors = {}

    if request.method == "POST":
        form_data, values, errors = _validate_form()
        if "title" not in errors and _title_exists(
            form_data["title"], excluded_threat_id=threat.ThreatId
        ):
            errors["title"] = "A threat with this title already exists."

        if not errors:
            _assign_values(threat, values)
            normalized_cve = normalize_cve_code(threat.CVE)
            if normalized_cve:
                CVEPersistenceService.sync_threat(
                    threat, [normalized_cve], source=threat.Source
                )
            db.session.commit()
            flash("Threat updated successfully.", "success")
            return redirect(url_for("threats.threat_list"))
    else:
        form_data = {
            "title": threat.Title,
            "vendor_id": str(threat.VendorId or ""),
            "source": threat.Source or "",
            "severity": threat.Severity or "",
            "cve": threat.CVE or "",
            "cvss": str(threat.CVSS) if threat.CVSS is not None else "",
            "kev": bool(threat.KEV),
            "published_date": (
                threat.PublishedDate.strftime("%Y-%m-%dT%H:%M")
                if threat.PublishedDate
                else ""
            ),
            "reference_url": threat.ReferenceUrl or "",
            "summary": threat.Summary or "",
            "recommendation": threat.Recommendation or "",
        }

    return render_template(
        "threat_form.html",
        page_title="Edit Threat",
        form_data=form_data,
        errors=errors,
        vendors=_get_vendors(),
        severity_options=SEVERITIES,
    )


@threats_blueprint.route("/threats/<int:threat_id>/delete", methods=["POST"])
def delete_threat(threat_id):
    threat = db.get_or_404(Threat, threat_id)
    referenced = db.session.scalar(
        db.select(SourceItem.SourceItemId)
        .where(SourceItem.ThreatId == threat_id)
        .limit(1)
    )
    if referenced is not None:
        flash("Threat cannot be deleted because it has source evidence.", "warning")
        return redirect(url_for("threats.threat_list"))

    try:
        db.session.delete(threat)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Threat cannot be deleted because it is in use.", "warning")
        return redirect(url_for("threats.threat_list"))

    flash("Threat deleted successfully.", "success")
    return redirect(url_for("threats.threat_list"))
