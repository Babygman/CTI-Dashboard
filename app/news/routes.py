from datetime import datetime
from urllib.parse import urlparse

from flask import flash, redirect, render_template, request, url_for

from app.extensions import db
from app.models.asset import Asset
from app.models.news_item import NewsItem
from app.services.relevance import assess_item, news_relevance, recommend

from . import news_blueprint

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
THREAT_TYPES = ("Advisory", "Vulnerability", "Phishing", "Ransomware", "Malware", "Scam", "Other")


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
    statement = db.select(NewsItem)
    if relevance == "relevant":
        statement = statement.where(NewsItem.IsRelevant == True)
    elif relevance == "not-relevant":
        statement = statement.where(NewsItem.IsRelevant == False)
    items = db.session.execute(
        statement.order_by(NewsItem.PublishedDate.desc(), NewsItem.NewsItemId.desc())
    ).scalars().all()
    return render_template("news/index.html", items=items, relevance=relevance)


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
