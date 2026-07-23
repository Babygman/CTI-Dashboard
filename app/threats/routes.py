from datetime import datetime
from decimal import Decimal, InvalidOperation
from math import ceil
from threading import Lock
from time import monotonic
from types import SimpleNamespace

from flask import flash, redirect, render_template, request, url_for
from sqlalchemy import and_, func, literal, not_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import load_only
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
from app.models.asset import Asset
from app.services.relevance import (
    USER_THREATS,
    _tokens,
    assess_item,
    normalize,
    recommend,
)

from . import threats_blueprint


SEVERITIES = ("Critical", "High", "Medium", "Low")
RELEVANT_THREAT_PAGE_SIZES = (25, 50, 100)
RELEVANT_THREAT_COUNT_CACHE_SECONDS = 30
_relevant_threat_count_cache = {}
_relevant_threat_count_cache_lock = Lock()


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


@threats_blueprint.get("/relevant-threats")
def relevant_threats():
    selected = request.args.get("filter", "relevant")
    allowed = {"relevant", "all", "affected", "possibly", "awareness", "patch", "monitor", "ignored"}
    if selected not in allowed:
        selected = "relevant"
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = request.args.get("per_page", 25, type=int)
    if per_page not in RELEVANT_THREAT_PAGE_SIZES:
        per_page = 25

    assets = db.session.execute(
        db.select(Asset)
        .options(
            load_only(
                Asset.AssetId,
                Asset.AssetName,
                Asset.Vendor,
                Asset.Product,
                Asset.Version,
            )
        )
        .where(Asset.Status == "Active")
        .order_by(Asset.AssetName)
    ).scalars().all()

    filter_expression = _relevant_threat_filter(selected, assets)
    total = _relevant_threat_count(
        selected,
        assets,
        filter_expression,
    )
    pages = ceil(total / per_page) if total else 0
    if pages and page > pages:
        page = pages

    primary_cve = (
        db.select(CVE.CVECode)
        .join(ThreatCVE, ThreatCVE.CVEId == CVE.CVEId)
        .where(ThreatCVE.ThreatId == Threat.ThreatId)
        .order_by(ThreatCVE.IsPrimary.desc(), ThreatCVE.CVEId.asc())
        .limit(1)
        .scalar_subquery()
    )
    threat_rows = db.session.execute(
        db.select(
            Threat.ThreatId,
            Threat.Title,
            Threat.Source,
            Threat.Severity,
            Threat.CVE,
            Threat.KEV,
            Threat.PublishedDate,
            Threat.ReferenceUrl,
            Threat.Summary,
            Threat.Recommendation,
            Vendor.VendorName,
            func.coalesce(primary_cve, Threat.CVE).label("PrimaryCVECode"),
        )
        .outerjoin(Vendor, Vendor.VendorId == Threat.VendorId)
        .where(filter_expression)
        .order_by(
            Threat.PublishedDate.desc(), Threat.ThreatId.desc()
        )
        .offset((page - 1) * per_page)
        .limit(per_page)
    ).all()

    rows = []
    for result in threat_rows:
        threat = SimpleNamespace(
            ThreatId=result.ThreatId,
            Title=result.Title,
            Source=result.Source,
            Severity=result.Severity,
            CVE=result.CVE,
            KEV=result.KEV,
            PublishedDate=result.PublishedDate,
            ReferenceUrl=result.ReferenceUrl,
            Summary=result.Summary,
            Recommendation=result.Recommendation,
            primary_cve_code=result.PrimaryCVECode,
            vendor=(
                SimpleNamespace(VendorName=result.VendorName)
                if result.VendorName
                else None
            ),
        )
        matches = []
        for asset in assets:
            status, reason = assess_item(threat, asset)
            if status != "Not Affected":
                action, action_reason = recommend(threat, status)
                matches.append((asset, status, reason, action, action_reason))
        if matches:
            rank = {"Affected": 0, "Possibly Affected": 1, "Needs Review": 2}
            asset, status, reason, action, action_reason = sorted(
                matches, key=lambda x: rank.get(x[1], 9)
            )[0]
        else:
            action, action_reason = recommend(threat, "Not Affected")
            asset, status, reason = None, "Not Affected", "No company asset matched."
        include = {
            "all": True, "relevant": bool(matches) or action == "Need Awareness",
            "affected": status == "Affected", "possibly": status == "Possibly Affected",
            "awareness": action == "Need Awareness", "patch": action == "Need Patch",
            "monitor": action == "Need Monitor", "ignored": action == "Ignore",
        }[selected]
        if include:
            rows.append({
                "threat": threat, "asset": asset, "status": status, "reason": reason,
                "action": action, "action_reason": action_reason,
            })
    return render_template(
        "relevant_threats.html",
        rows=rows,
        selected=selected,
        page=page,
        pages=pages,
        per_page=per_page,
        page_sizes=RELEVANT_THREAT_PAGE_SIZES,
        total=total,
    )


def _relevant_threat_filter(selected, assets):
    searchable_fields = (
        Threat.Title,
        Threat.Summary,
        Threat.Recommendation,
        Threat.Source,
    )

    def contains(value):
        normalized = " ".join(
            token
            for token in normalize(value).split()
            if token
        )
        return (
            or_(
                *(
                    func.coalesce(field, "").contains(
                        normalized,
                        autoescape=True,
                    )
                    for field in searchable_fields
                )
            )
            if normalized
            else literal(False)
        )

    user_targeted = or_(*(contains(term) for term in USER_THREATS))
    asset_matches = []
    affected_matches = []
    possibly_matches = []

    for asset in assets:
        vendor_match = contains(asset.Vendor)
        product_tokens = _tokens(asset.Product or asset.AssetName)
        product_match = (
            and_(*(contains(token) for token in product_tokens))
            if product_tokens
            else literal(False)
        )
        version_value = normalize(asset.Version)
        version_match = contains(version_value)

        asset_matches.append(or_(vendor_match, product_match))
        affected_matches.append(
            and_(
                product_match,
                or_(not_(literal(bool(version_value))), version_match),
            )
        )
        possibly_matches.append(
            or_(
                and_(product_match, literal(bool(version_value)), not_(version_match)),
                and_(not_(product_match), vendor_match),
            )
        )

    matched = or_(*asset_matches) if asset_matches else literal(False)
    affected = or_(*affected_matches) if affected_matches else literal(False)
    possibly = or_(*possibly_matches) if possibly_matches else literal(False)
    high_priority = or_(
        Threat.KEV == True,  # noqa: E712 - SQLAlchemy compiles this as "= 1" for MSSQL.
        func.lower(func.coalesce(Threat.Severity, "")).in_(("critical", "high")),
    )
    configuration_guidance = or_(
        contains("configuration"),
        contains("mitigation"),
        contains("workaround"),
    )
    patch = and_(not_(user_targeted), matched, high_priority)
    monitor = and_(
        not_(user_targeted),
        matched,
        not_(high_priority),
        not_(configuration_guidance),
    )

    return {
        "all": literal(True),
        "relevant": or_(matched, user_targeted),
        "affected": affected,
        "possibly": possibly,
        "awareness": user_targeted,
        "patch": patch,
        "monitor": monitor,
        "ignored": and_(not_(user_targeted), not_(matched)),
    }[selected]


def _relevant_threat_count(selected, assets, filter_expression):
    asset_key = tuple(
        (
            asset.AssetId,
            asset.AssetName,
            asset.Vendor,
            asset.Product,
            asset.Version,
        )
        for asset in assets
    )
    cache_key = (id(db.engine), selected, asset_key)
    now = monotonic()

    with _relevant_threat_count_cache_lock:
        expired_keys = [
            key
            for key, value in _relevant_threat_count_cache.items()
            if now - value["created_at"]
            >= RELEVANT_THREAT_COUNT_CACHE_SECONDS
        ]
        for key in expired_keys:
            _relevant_threat_count_cache.pop(key, None)
        cached = _relevant_threat_count_cache.get(cache_key)
        if (
            cached
            and now - cached["created_at"]
            < RELEVANT_THREAT_COUNT_CACHE_SECONDS
        ):
            return cached["total"]

    total = db.session.scalar(
        db.select(func.count())
        .select_from(Threat)
        .where(filter_expression)
    ) or 0

    with _relevant_threat_count_cache_lock:
        _relevant_threat_count_cache[cache_key] = {
            "created_at": now,
            "total": total,
        }

    return total


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
