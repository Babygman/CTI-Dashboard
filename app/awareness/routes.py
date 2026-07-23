from flask import (
    Blueprint,
    abort,
    render_template,
    request,
    send_file,
    flash,
    redirect,
    url_for,
)

from app.extensions import db
from app.exports.infographic_export import InfographicExporter
from app.exports.pdf_export import PDFExporter
from app.exports.ppt_export import PowerPointExporter
from app.exports.word_export import WordExporter
from app.services.awareness_service import AwarenessGenerator
from app.models.threat import Threat
from app.models.news_item import NewsItem
from app.models.awareness_record import AwarenessRecord


awareness_bp = Blueprint(
    "awareness",
    __name__,
    url_prefix="/awareness",
)


def get_threat(threat_id=None):
    threat = (
        db.session.get(Threat, threat_id)
        if threat_id
        else db.session.execute(
            db.select(Threat).order_by(
                Threat.PublishedDate.desc(), Threat.ThreatId.desc()
            ).limit(1)
        ).scalar_one_or_none()
    )
    if threat is None:
        return None
    return {
        field: getattr(threat, field)
        for field in (
            "ThreatId", "Title", "Source", "Severity", "CVE", "CVSS", "KEV",
            "PublishedDate", "ReferenceUrl", "Summary", "Recommendation",
        )
    }


@awareness_bp.route("/", methods=["GET"])
def index():
    threat_id = request.args.get("threat_id", type=int)

    threat = get_threat(threat_id)

    if threat is None and threat_id:
        threat = get_threat()

    executive_summary = None
    business_impact = None
    it_recommendation = None
    email_subject = None

    if threat:
        threat_dict = dict(threat)

        executive_summary = AwarenessGenerator.executive_summary(
            threat_dict
        )

        business_impact = AwarenessGenerator.business_impact(
            threat_dict
        )

        it_recommendation = AwarenessGenerator.it_recommendation(
            threat_dict
        )

        email_subject = AwarenessGenerator.email_subject(
            threat_dict
        )

    return render_template(
        "awareness.html",
        threat=threat,
        executive_summary=executive_summary,
        business_impact=business_impact,
        it_recommendation=it_recommendation,
        email_subject=email_subject,
    )


def _record_defaults(source):
    threat_dict = {
        "Title": source.Title,
        "Summary": source.Summary,
        "Severity": source.Severity,
        "CVE": getattr(source, "CVE", None),
        "Source": source.Source,
        "Recommendation": getattr(source, "Recommendation", None),
    }
    content = AwarenessGenerator.infographic_content(threat_dict)
    return {
        "Title": content["headline"],
        "ThaiExplanation": getattr(source, "ThaiSummary", None)
        or f"คำเตือนด้านความปลอดภัยเกี่ยวกับ {source.Title}",
        "WhatHappened": content["what_happened"],
        "WhoAffected": getattr(source, "UserImpact", None)
        or "พนักงานและผู้ใช้งานระบบที่เกี่ยวข้อง",
        "MustDo": "\n".join(content["actions"]),
        "MustNotDo": "\n".join(content["avoid"]),
        "ReportToIT": content["contact_it"],
        "ReferenceUrl": source.ReferenceUrl,
        "Severity": source.Severity,
    }


@awareness_bp.get("/records")
def records():
    items = db.session.execute(
        db.select(AwarenessRecord).order_by(
            AwarenessRecord.CreatedAt.desc(), AwarenessRecord.AwarenessRecordId.desc()
        )
    ).scalars().all()
    return render_template("awareness/records.html", records=items)


@awareness_bp.get("/create/threat/<int:threat_id>")
def create_from_threat(threat_id):
    threat = db.get_or_404(Threat, threat_id)
    record = AwarenessRecord(ThreatId=threat_id, **_record_defaults(threat))
    db.session.add(record)
    db.session.commit()
    return redirect(url_for("awareness.edit_record", record_id=record.AwarenessRecordId))


@awareness_bp.get("/create/news/<int:news_id>")
def create_from_news(news_id):
    news = db.get_or_404(NewsItem, news_id)
    record = AwarenessRecord(NewsItemId=news_id, **_record_defaults(news))
    db.session.add(record)
    db.session.commit()
    return redirect(url_for("awareness.edit_record", record_id=record.AwarenessRecordId))


@awareness_bp.route("/records/<int:record_id>/edit", methods=["GET", "POST"])
def edit_record(record_id):
    record = db.get_or_404(AwarenessRecord, record_id)
    fields = (
        "Title", "ThaiExplanation", "WhatHappened", "WhoAffected", "MustDo",
        "MustNotDo", "ReportToIT", "ReferenceUrl", "Severity", "Status",
        "DocumentVersion",
    )
    if request.method == "POST":
        for field in fields:
            value = request.form.get(field, "").strip()
            if field in {"Title", "ThaiExplanation", "WhatHappened", "WhoAffected",
                         "MustDo", "MustNotDo", "ReportToIT"} and not value:
                flash("All awareness content fields are required.", "danger")
                break
            setattr(record, field, value or None)
        else:
            if record.Status not in {"Draft", "Ready"}:
                record.Status = "Draft"
            db.session.commit()
            flash("Awareness saved.", "success")
            return redirect(url_for("awareness.preview_record", record_id=record_id))
    return render_template("awareness/record_form.html", record=record)


@awareness_bp.get("/records/<int:record_id>/preview")
def preview_record(record_id):
    return render_template(
        "awareness/record_preview.html",
        record=db.get_or_404(AwarenessRecord, record_id),
    )


def _record_export_data(record):
    return {
        "ThreatId": record.AwarenessRecordId,
        "Title": record.Title,
        "Severity": record.Severity,
        "CVE": "",
        "CVSS": "",
        "Source": record.news_item.Source if record.news_item else (
            record.threat.Source if record.threat else "Corporate Awareness"
        ),
        "PublishedDate": record.CreatedAt,
        "ReferenceUrl": record.ReferenceUrl,
        "Summary": record.ThaiExplanation,
        "Recommendation": record.MustDo,
    }


@awareness_bp.get("/records/<int:record_id>/pdf")
def record_pdf(record_id):
    record = db.get_or_404(AwarenessRecord, record_id)
    data = _record_export_data(record)
    output, filename = PDFExporter.generate(
        threat=data,
        executive_summary=f"{record.ThaiExplanation}\n\n{record.WhatHappened}\n\nผู้ที่อาจได้รับผลกระทบ: {record.WhoAffected}",
        business_impact=[line for line in record.MustNotDo.splitlines() if line],
        it_recommendation=f"{record.MustDo}\n\nรายงานต่อ IT: {record.ReportToIT}",
    )
    return send_file(output, as_attachment=True, download_name=filename, mimetype="application/pdf")


@awareness_bp.get("/records/<int:record_id>/png")
def record_png(record_id):
    record = db.get_or_404(AwarenessRecord, record_id)
    data = _record_export_data(record)
    content = {
        "headline": record.Title,
        "what_happened": record.WhatHappened,
        "why_it_matters": record.WhoAffected,
        "actions": record.MustDo.splitlines(),
        "avoid": record.MustNotDo.splitlines(),
        "contact_it": record.ReportToIT,
    }
    output, filename = InfographicExporter.generate(data, content)
    return send_file(output, as_attachment=True, download_name=filename, mimetype="image/png")


@awareness_bp.route(
    "/export/word/<int:threat_id>",
    methods=["GET"],
)
def export_word(threat_id):
    threat = get_threat(threat_id)

    if threat is None:
        abort(404)

    threat_dict = dict(threat)

    executive_summary = AwarenessGenerator.executive_summary(
        threat_dict
    )

    business_impact = AwarenessGenerator.business_impact(
        threat_dict
    )

    it_recommendation = AwarenessGenerator.it_recommendation(
        threat_dict
    )

    output, filename = WordExporter.generate(
        threat=threat_dict,
        executive_summary=executive_summary,
        business_impact=business_impact,
        it_recommendation=it_recommendation,
    )

    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "wordprocessingml.document"
        ),
    )


@awareness_bp.route(
    "/export/pdf/<int:threat_id>",
    methods=["GET"],
)
def export_pdf(threat_id):
    threat = get_threat(threat_id)

    if threat is None:
        abort(404)

    threat_dict = dict(threat)

    executive_summary = AwarenessGenerator.executive_summary(
        threat_dict
    )

    business_impact = AwarenessGenerator.business_impact(
        threat_dict
    )

    it_recommendation = AwarenessGenerator.it_recommendation(
        threat_dict
    )

    output, filename = PDFExporter.generate(
        threat=threat_dict,
        executive_summary=executive_summary,
        business_impact=business_impact,
        it_recommendation=it_recommendation,
    )

    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )


@awareness_bp.route(
    "/export/ppt/<int:threat_id>",
    methods=["GET"],
)
def export_ppt(threat_id):
    threat = get_threat(threat_id)

    if threat is None:
        abort(404)

    threat_dict = dict(threat)

    executive_summary = AwarenessGenerator.executive_summary(
        threat_dict
    )

    business_impact = AwarenessGenerator.business_impact(
        threat_dict
    )

    it_recommendation = AwarenessGenerator.it_recommendation(
        threat_dict
    )

    output, filename = PowerPointExporter.generate(
        threat=threat_dict,
        executive_summary=executive_summary,
        business_impact=business_impact,
        it_recommendation=it_recommendation,
    )

    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "presentationml.presentation"
        ),
    )

@awareness_bp.route(
    "/export/infographic/<int:threat_id>",
    methods=["GET"],
)
def export_infographic(threat_id):
    threat = get_threat(threat_id)

    if threat is None:
        abort(404)

    threat_dict = dict(threat)
    infographic_content = AwarenessGenerator.infographic_content(threat_dict)

    output, filename = InfographicExporter.generate(
        threat=threat_dict,
        infographic_content=infographic_content,
    )

    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype="image/png",
    )
