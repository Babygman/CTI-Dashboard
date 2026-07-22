from flask import (
    Blueprint,
    abort,
    render_template,
    request,
    send_file,
)
from sqlalchemy import text

from app.extensions import db
from app.exports.infographic_export import InfographicExporter
from app.exports.pdf_export import PDFExporter
from app.exports.ppt_export import PowerPointExporter
from app.exports.word_export import WordExporter
from app.services.awareness_service import AwarenessGenerator


awareness_bp = Blueprint(
    "awareness",
    __name__,
    url_prefix="/awareness",
)


def get_threat(threat_id=None):
    if threat_id:
        return db.session.execute(
            text(
                """
                SELECT TOP 1
                    ThreatId,
                    Title,
                    Source,
                    Severity,
                    CVE,
                    CVSS,
                    KEV,
                    PublishedDate,
                    ReferenceUrl,
                    Summary,
                    Recommendation
                FROM Threats
                WHERE ThreatId = :threat_id
                """
            ),
            {"threat_id": threat_id},
        ).mappings().first()

    return db.session.execute(
        text(
            """
            SELECT TOP 1
                ThreatId,
                Title,
                Source,
                Severity,
                CVE,
                CVSS,
                KEV,
                PublishedDate,
                ReferenceUrl,
                Summary,
                Recommendation
            FROM Threats
            ORDER BY PublishedDate DESC, ThreatId DESC
            """
        )
    ).mappings().first()


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
