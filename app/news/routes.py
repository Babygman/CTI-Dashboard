from datetime import datetime, timedelta
from urllib.parse import urlparse

from math import ceil
from types import SimpleNamespace

from flask import flash, redirect, render_template, request, url_for
from sqlalchemy import func, literal, not_, or_

from app.extensions import db
from app.models.asset import Asset
from app.models.cve import CVE
from app.models.news_item import NewsItem
from app.models.source_item import SourceItem
from app.models.threat import Threat
from app.models.threat_cve import ThreatCVE
from app.models.vendor import Vendor
from app.services.relevance import assess_item, news_relevance, recommend

from . import news_blueprint

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
THREAT_TYPES = ("Advisory", "Vulnerability", "Phishing", "Ransomware", "Malware", "Scam", "Other")
NEWS_PAGE_SIZES = (25, 50, 100)


def _date_filter(name):
    value = request.args.get(name, "").strip()
    if not value:
        return "", None
    try:
        return value, datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return "", None


def _source_options():
    sources = db.select(NewsItem.Source.label("Source")).where(
        NewsItem.Source.is_not(None)
    ).union(
        db.select(Threat.Source.label("Source")).where(
            Threat.Source.is_not(None)
        )
    ).subquery()
    return db.session.scalars(
        db.select(sources.c.Source)
        .where(sources.c.Source != "")
        .distinct()
        .order_by(sources.c.Source)
    ).all()


def _form(item=None):
    return {
        "title": request.form.get("title", getattr(item, "Title", "") or "").strip(),
        "source": request.form.get("source", getattr(item, "Source", "") or "").strip(),
        "reference_url": request.form.get("reference_url", getattr(item, "ReferenceUrl", "") or "").strip(),
        "published_date": request.form.get(
            "published_date",
            item.PublishedDate.strftime("%Y-%m-%d") if item and item.PublishedDate else "",
        ).strip(),
        "summary": request.form.get("summary", getattr(item, "Summary", "") or "").strip(),
        "thai_summary": request.form.get("thai_summary", getattr(item, "ThaiSummary", "") or "").strip(),
        "vendor": request.form.get("vendor", getattr(item, "Vendor", "") or "").strip(),
        "product": request.form.get("product", getattr(item, "Product", "") or "").strip(),
        "cve": request.form.get("cve", getattr(item, "CVE", "") or "").strip(),
        "severity": request.form.get("severity", getattr(item, "Severity", "") or "").strip(),
        "threat_type": request.form.get("threat_type", getattr(item, "ThreatType", "") or "").strip(),
        "user_impact": request.form.get("user_impact", getattr(item, "UserImpact", "") or "").strip(),
        "it_impact": request.form.get("it_impact", getattr(item, "ITImpact", "") or "").strip(),
        "recommendation_type": request.form.get("recommendation_type", getattr(item, "RecommendationType", "") or "").strip(),
        "recommendation_reason": request.form.get("recommendation_reason", getattr(item, "RecommendationReason", "") or "").strip(),
    }


def _validate(form):
    errors = {}
    if not form["title"] or len(form["title"]) > 500:
        errors["title"] = "Title is required and must be 500 characters or fewer."
    if not form["source"] or len(form["source"]) > 200:
        errors["source"] = "Source is required and must be 200 characters or fewer."
    parsed = urlparse(form["reference_url"])
    if not form["reference_url"] or parsed.scheme not in {"http", "https"} or not parsed.netloc:
        errors["reference_url"] = "Enter a valid http or https URL."
    if form["severity"] and form["severity"] not in SEVERITIES:
        errors["severity"] = "Select a valid severity."
    if form["threat_type"] and form["threat_type"] not in THREAT_TYPES:
        errors["threat_type"] = "Select a valid threat type."
    try:
        published = datetime.strptime(form["published_date"], "%Y-%m-%d") if form["published_date"] else None
    except ValueError:
        errors["published_date"] = "Enter a valid date."
        published = None
    return errors, published


def _apply(item, form, published):
    mapping = {
        "Title": "title", "Source": "source", "ReferenceUrl": "reference_url",
        "Summary": "summary", "ThaiSummary": "thai_summary", "Vendor": "vendor",
        "Product": "product", "CVE": "cve", "Severity": "severity",
        "ThreatType": "threat_type", "UserImpact": "user_impact", "ITImpact": "it_impact",
        "RecommendationType": "recommendation_type", "RecommendationReason": "recommendation_reason",
    }
    for attr, key in mapping.items():
        setattr(item, attr, form[key] or None)
    item.PublishedDate = published
    assets = db.session.execute(db.select(Asset).where(Asset.Status == "Active")).scalars().all()
    item.IsRelevant, relevance_reason = news_relevance(item, assets)
    if not item.RecommendationType:
        item.RecommendationType, item.RecommendationReason = recommend(
            item, "Affected" if item.IsRelevant else "Not Affected"
        )
    if not item.RecommendationReason:
        item.RecommendationReason = relevance_reason
    if not item.ThaiSummary:
        item.ThaiSummary = f"ประกาศความปลอดภัย: {item.Summary or item.Title}"


@news_blueprint.get("/")
def index():
    relevance = request.args.get("relevance", "")
    if relevance not in {"relevant", "not-relevant"}:
        relevance = ""
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = request.args.get("per_page", 25, type=int)
    if per_page not in NEWS_PAGE_SIZES:
        per_page = 25
    query = request.args.get("q", "").strip()
    source = request.args.get("source", "").strip()
    severity = request.args.get("severity", "").strip()
    if severity not in SEVERITIES:
        severity = ""
    recommendation = request.args.get("recommendation", "").strip()
    date_from, date_from_value = _date_filter("date_from")
    date_to, date_to_value = _date_filter("date_to")

    assets = db.session.execute(
        db.select(Asset).where(Asset.Status == "Active")
    ).scalars().all()
    from app.threats.routes import (
        RELEVANT_THREAT_RECOMMENDATIONS,
        _relevant_threat_expressions,
    )

    expressions = _relevant_threat_expressions(assets)
    if recommendation not in RELEVANT_THREAT_RECOMMENDATIONS:
        recommendation = ""
    manual_news = db.select(
        literal("news").label("RecordType"),
        NewsItem.NewsItemId.label("RecordId"),
        NewsItem.Title,
        NewsItem.Source,
        NewsItem.PublishedDate,
        NewsItem.ThreatType,
        NewsItem.Severity,
        NewsItem.IsRelevant,
        NewsItem.RecommendationType,
        NewsItem.ReferenceUrl,
        NewsItem.Summary,
        NewsItem.RecommendationReason.label("RawRecommendation"),
        literal(False).label("KEV"),
    )
    collected_threats = db.select(
        literal("threat").label("RecordType"),
        Threat.ThreatId.label("RecordId"),
        Threat.Title,
        Threat.Source,
        Threat.PublishedDate,
        literal("Vulnerability").label("ThreatType"),
        Threat.Severity,
        literal(None).label("IsRelevant"),
        literal(None).label("RecommendationType"),
        Threat.ReferenceUrl,
        Threat.Summary,
        Threat.Recommendation.label("RawRecommendation"),
        Threat.KEV,
    )
    if query:
        pattern = f"%{query}%"
        manual_news = manual_news.where(
            or_(
                NewsItem.Title.ilike(pattern),
                NewsItem.Summary.ilike(pattern),
                NewsItem.Vendor.ilike(pattern),
                NewsItem.Product.ilike(pattern),
                NewsItem.CVE.ilike(pattern),
                NewsItem.Source.ilike(pattern),
            )
        )
        collected_threats = collected_threats.outerjoin(
            Vendor, Vendor.VendorId == Threat.VendorId
        ).where(
            or_(
                Threat.Title.ilike(pattern),
                Threat.Summary.ilike(pattern),
                Vendor.VendorName.ilike(pattern),
                Threat.CVE.ilike(pattern),
                Threat.Source.ilike(pattern),
                Threat.cve_links.any(
                    ThreatCVE.cve.has(CVE.CVECode.ilike(pattern))
                ),
                db.select(SourceItem.SourceItemId)
                .where(
                    SourceItem.ThreatId == Threat.ThreatId,
                    or_(
                        SourceItem.Title.ilike(pattern),
                        SourceItem.CVE.ilike(pattern),
                        SourceItem.NormalizedMetadata.ilike(pattern),
                    ),
                )
                .exists(),
            )
        )
    if source:
        manual_news = manual_news.where(NewsItem.Source == source)
        collected_threats = collected_threats.where(Threat.Source == source)
    if severity:
        manual_news = manual_news.where(NewsItem.Severity == severity)
        collected_threats = collected_threats.where(
            Threat.Severity == severity
        )
    if recommendation:
        manual_news = manual_news.where(
            NewsItem.RecommendationType == recommendation
        )
        collected_threats = collected_threats.where(
            expressions["recommendations"][recommendation]
        )
    if date_from_value:
        manual_news = manual_news.where(
            NewsItem.PublishedDate >= date_from_value
        )
        collected_threats = collected_threats.where(
            Threat.PublishedDate >= date_from_value
        )
    if date_to_value:
        exclusive_end = date_to_value + timedelta(days=1)
        manual_news = manual_news.where(
            NewsItem.PublishedDate < exclusive_end
        )
        collected_threats = collected_threats.where(
            Threat.PublishedDate < exclusive_end
        )
    if relevance == "relevant":
        manual_news = manual_news.where(NewsItem.IsRelevant == True)
        collected_threats = collected_threats.where(
            expressions["relevant"]
        )
    elif relevance == "not-relevant":
        manual_news = manual_news.where(NewsItem.IsRelevant == False)
        collected_threats = collected_threats.where(
            not_(expressions["relevant"])
        )
    filter_query = {
        key: value
        for key, value in {
            "q": query,
            "source": source,
            "severity": severity,
            "recommendation": recommendation,
            "date_from": date_from,
            "date_to": date_to,
            "per_page": per_page,
        }.items()
        if value not in ("", None)
    }
    page_size_query = {
        key: value
        for key, value in filter_query.items()
        if key != "per_page"
    }
    feed = manual_news.union_all(collected_threats).subquery()
    statement = db.select(feed)
    total = db.session.scalar(
        db.select(func.count()).select_from(statement.subquery())
    ) or 0
    pages = ceil(total / per_page) if total else 0
    if pages and page > pages:
        page = pages
    feed_rows = db.session.execute(
        statement.order_by(
            feed.c.PublishedDate.desc(),
            feed.c.RecordType.asc(),
            feed.c.RecordId.desc(),
        )
        .offset((page - 1) * per_page)
        .limit(per_page)
    ).all()
    items = []
    for row in feed_rows:
        if row.RecordType == "news":
            items.append(row)
            continue
        threat = SimpleNamespace(
            Title=row.Title,
            Summary=row.Summary,
            Recommendation=row.RawRecommendation,
            Source=row.Source,
            Severity=row.Severity,
            KEV=row.KEV,
        )
        matches = [
            status
            for asset in assets
            for status, _ in [assess_item(threat, asset)]
            if status != "Not Affected"
        ]
        if matches:
            rank = {
                "Affected": 0,
                "Possibly Affected": 1,
                "Needs Review": 2,
            }
            status = sorted(
                matches,
                key=lambda value: rank.get(value, 9),
            )[0]
        else:
            status = "Not Affected"
        recommendation_type, _ = recommend(threat, status)
        row_values = dict(row._mapping)
        row_values["IsRelevant"] = bool(matches) or (
            recommendation_type == "Need Awareness"
        )
        row_values["RecommendationType"] = recommendation_type
        items.append(SimpleNamespace(**row_values))
    return render_template(
        "news/index.html",
        items=items,
        relevance=relevance,
        page=page,
        pages=pages,
        per_page=per_page,
        page_sizes=NEWS_PAGE_SIZES,
        total=total,
        q=query,
        sources=_source_options(),
        selected_source=source,
        severity_options=SEVERITIES,
        selected_severity=severity,
        recommendation_options=RELEVANT_THREAT_RECOMMENDATIONS,
        selected_recommendation=recommendation,
        date_from=date_from,
        date_to=date_to,
        filter_query=filter_query,
        page_size_query=page_size_query,
    )


@news_blueprint.route("/add", methods=["GET", "POST"])
def add():
    form = _form()
    errors = {}
    if request.method == "POST":
        errors, published = _validate(form)
        if not errors:
            item = NewsItem()
            _apply(item, form, published)
            db.session.add(item)
            db.session.commit()
            flash("News item added.", "success")
            return redirect(url_for("news.detail", news_id=item.NewsItemId))
    return render_template("news/form.html", form=form, errors=errors, page_title="Add News",
                           severities=SEVERITIES, threat_types=THREAT_TYPES)


@news_blueprint.get("/<int:news_id>")
def detail(news_id):
    item = db.get_or_404(NewsItem, news_id)
    assets = db.session.execute(
        db.select(Asset)
        .where(Asset.Status == "Active")
        .order_by(Asset.AssetName.asc())
    ).scalars().all()
    matches = []
    for asset in assets:
        status, reason = assess_item(item, asset)
        if status != "Not Affected":
            matches.append({"asset": asset, "status": status, "reason": reason})
    return render_template("news/detail.html", item=item, matches=matches)


@news_blueprint.route("/<int:news_id>/edit", methods=["GET", "POST"])
def edit(news_id):
    item = db.get_or_404(NewsItem, news_id)
    form = _form(item)
    errors = {}
    if request.method == "POST":
        errors, published = _validate(form)
        if not errors:
            _apply(item, form, published)
            db.session.commit()
            flash("News item updated.", "success")
            return redirect(url_for("news.detail", news_id=news_id))
    return render_template("news/form.html", form=form, errors=errors, page_title="Edit News",
                           severities=SEVERITIES, threat_types=THREAT_TYPES)


@news_blueprint.post("/<int:news_id>/relevance")
def relevance(news_id):
    item = db.get_or_404(NewsItem, news_id)
    item.IsRelevant = request.form.get("is_relevant") == "true"
    db.session.commit()
    return redirect(url_for("news.detail", news_id=news_id))


@news_blueprint.post("/<int:news_id>/delete")
def delete(news_id):
    item = db.get_or_404(NewsItem, news_id)
    db.session.delete(item)
    db.session.commit()
    flash("News item deleted.", "success")
    return redirect(url_for("news.index"))
