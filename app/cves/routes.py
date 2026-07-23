from decimal import Decimal, InvalidOperation

from flask import render_template, request

from app.repositories import CVERepository
from app.services.cve_service import CVEDetailService

from . import cves_blueprint


SEVERITIES = ("Critical", "High", "Medium", "Low")


def _score(name):
    value = request.args.get(name, "").strip()
    if not value:
        return None
    try:
        score = Decimal(value)
    except InvalidOperation:
        return None
    return score if Decimal("0") <= score <= Decimal("10") else None


@cves_blueprint.get("/cves/")
def cve_list():
    search = request.args.get("q", "").strip().upper()
    severity = request.args.get("severity", "").strip()
    if severity not in SEVERITIES:
        severity = ""
    minimum = _score("cvss_min")
    maximum = _score("cvss_max")
    rows = CVERepository.list_cves(
        search=search,
        severity=severity,
        minimum=minimum,
        maximum=maximum,
    )
    # Assets are loaded once; counts are then derived in memory.
    assets = CVERepository.all_assets()
    asset_counts = {}
    for cve, _ in rows:
        threats = [link.threat for link in cve.threat_links]
        asset_counts[cve.CVEId] = len(
            CVEDetailService._related_assets(threats, assets)
        )
    return render_template(
        "cves.html",
        rows=rows,
        asset_counts=asset_counts,
        q=search,
        selected_severity=severity,
        cvss_min=request.args.get("cvss_min", ""),
        cvss_max=request.args.get("cvss_max", ""),
        severity_options=SEVERITIES,
    )


@cves_blueprint.get("/cves/<int:cve_id>")
def cve_detail(cve_id):
    detail = CVEDetailService().get(cve_id)
    if detail is None:
        return "", 404
    return render_template("cve_detail.html", detail=detail)

