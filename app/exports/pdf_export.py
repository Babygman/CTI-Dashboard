from datetime import datetime
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse

from flask import current_app
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4, LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from app.models.system_setting import SystemSetting


class PDFExporter:
    """Generate enterprise PDF security advisories."""

    DEFAULT_PRIMARY_COLOR = "0D6EFD"
    DEFAULT_SECONDARY_COLOR = "6C757D"
    FONT = "Helvetica"
    FONT_BOLD = "Helvetica-Bold"

    @classmethod
    def _ensure_thai_fonts(cls):
        candidates = (
            (r"C:\Windows\Fonts\tahoma.ttf", r"C:\Windows\Fonts\tahomabd.ttf"),
            ("/System/Library/Fonts/Supplemental/Tahoma.ttf",
             "/System/Library/Fonts/Supplemental/Tahoma Bold.ttf"),
            ("/usr/share/fonts/truetype/noto/NotoSansThai-Regular.ttf",
             "/usr/share/fonts/truetype/noto/NotoSansThai-Bold.ttf"),
        )
        for regular, bold in candidates:
            if Path(regular).is_file() and Path(bold).is_file():
                try:
                    pdfmetrics.registerFont(TTFont("CTIThai", regular))
                    pdfmetrics.registerFont(TTFont("CTIThai-Bold", bold))
                    cls.FONT, cls.FONT_BOLD = "CTIThai", "CTIThai-Bold"
                    return
                except Exception:
                    continue

    @staticmethod
    def generate(
        threat,
        executive_summary,
        business_impact,
        it_recommendation,
    ):
        PDFExporter._ensure_thai_fonts()
        settings = PDFExporter._load_settings()

        company_name = PDFExporter._setting(
            settings,
            "CompanyName",
            "DEFAULT_COMPANY_NAME",
            "Sunstar Chemical (Thailand) Co., Ltd.",
        )
        company_short_name = PDFExporter._setting(
            settings,
            "CompanyShortName",
            "DEFAULT_COMPANY_SHORT_NAME",
            "SUNSTAR",
        )
        department = PDFExporter._setting(
            settings,
            "Department",
            "DEFAULT_DEPARTMENT",
            "Information Technology Department",
        )
        classification = PDFExporter._localized_classification(
            PDFExporter._setting(
                settings,
                "Classification",
                "DEFAULT_CLASSIFICATION",
                "ใช้ภายในองค์กร",
            )
        )
        paper_size = settings.get("PaperSize", "A4")
        company_logo = settings.get("CompanyLogo", "")

        primary_color = PDFExporter._parse_hex_color(
            settings.get("PrimaryColor"),
            PDFExporter.DEFAULT_PRIMARY_COLOR,
        )
        secondary_color = PDFExporter._parse_hex_color(
            settings.get("SecondaryColor"),
            PDFExporter.DEFAULT_SECONDARY_COLOR,
        )

        page_size = (
            LETTER
            if str(paper_size).upper() == "LETTER"
            else A4
        )

        output = BytesIO()

        document = SimpleDocTemplate(
            output,
            pagesize=page_size,
            leftMargin=2.2 * cm,
            rightMargin=2.2 * cm,
            topMargin=3.5 * cm,
            bottomMargin=2.8 * cm,
            title=(
                "ประกาศด้านความมั่นคงปลอดภัยไซเบอร์ - "
                f"{threat.get('CVE') or 'ไม่ระบุ CVE'}"
            ),
            author=department,
            subject=(
                threat.get("Title")
                or "ประกาศด้านความมั่นคงปลอดภัยไซเบอร์"
            ),
            creator=f"{company_name} Awareness Platform",
        )

        styles = PDFExporter._build_styles(
            primary_color=primary_color,
            secondary_color=secondary_color,
        )

        story = []

        story.append(
            PDFExporter._classification_banner(
                classification=classification,
                primary_color=primary_color,
                width=document.width,
                styles=styles,
            )
        )
        story.append(Spacer(1, 0.35 * cm))

        story.append(
            Paragraph(
                "ประกาศด้านความมั่นคงปลอดภัยไซเบอร์",
                styles["title"],
            )
        )

        cve = threat.get("CVE") or "ไม่ระบุ CVE"
        severity = PDFExporter._localized_severity(
            threat.get("Severity")
        )

        story.append(
            Paragraph(
                (
                    f"{PDFExporter._escape(cve)} | "
                    f"ระดับความรุนแรง: {PDFExporter._escape(severity)}"
                ),
                styles["subtitle"],
            )
        )
        story.append(Spacer(1, 0.25 * cm))

        story.extend(
            PDFExporter._threat_information(
                threat=threat,
                width=document.width,
                primary_color=primary_color,
                styles=styles,
            )
        )

        story.extend(
            PDFExporter._content_section(
                heading="สรุปเหตุการณ์",
                content=(
                    executive_summary
                    or "ไม่มีข้อมูลสรุปเหตุการณ์"
                ),
                width=document.width,
                primary_color=primary_color,
                styles=styles,
            )
        )

        story.extend(
            PDFExporter._business_impact(
                business_impact=business_impact,
                width=document.width,
                primary_color=primary_color,
                styles=styles,
            )
        )

        story.extend(
            PDFExporter._content_section(
                heading="คำแนะนำจากฝ่าย IT",
                content=(
                    it_recommendation
                    or "ไม่มีคำแนะนำจากฝ่าย IT"
                ),
                width=document.width,
                primary_color=primary_color,
                styles=styles,
            )
        )

        story.extend(
            PDFExporter._source_reference(
                threat=threat,
                width=document.width,
                primary_color=primary_color,
                styles=styles,
            )
        )

        def draw_page(canvas, doc):
            PDFExporter._draw_header_footer(
                canvas=canvas,
                doc=doc,
                company_name=company_name,
                company_short_name=company_short_name,
                department=department,
                classification=classification,
                company_logo=company_logo,
                primary_color=primary_color,
                secondary_color=secondary_color,
            )

        document.build(
            story,
            onFirstPage=draw_page,
            onLaterPages=draw_page,
        )

        output.seek(0)

        safe_cve = PDFExporter._safe_filename(str(cve))
        filename = f"Security_Advisory_{safe_cve}.pdf"

        return output, filename

    @staticmethod
    def _load_settings():
        settings = (
            SystemSetting.query
            .filter_by(IsActive=True)
            .all()
        )

        return {
            setting.SettingKey: setting.SettingValue or ""
            for setting in settings
        }

    @staticmethod
    def _setting(settings, setting_key, config_key, default):
        value = str(settings.get(setting_key) or "").strip()
        if value:
            return value
        return str(current_app.config.get(config_key, default) or default).strip()

    @staticmethod
    def _localized_classification(value):
        return {
            "Internal Use": "ใช้ภายในองค์กร",
            "Confidential": "ข้อมูลลับ",
            "Public": "เผยแพร่สาธารณะ",
        }.get(str(value or "").strip(), str(value or "ใช้ภายในองค์กร"))

    @staticmethod
    def _localized_severity(value):
        return {
            "Critical": "วิกฤต",
            "High": "สูง",
            "Medium": "ปานกลาง",
            "Low": "ต่ำ",
            "Informational": "ข้อมูลทั่วไป",
        }.get(str(value or "").strip(), str(value or "ไม่ทราบระดับ"))

    @staticmethod
    def _build_styles(primary_color, secondary_color):
        base = getSampleStyleSheet()

        return {
            "title": ParagraphStyle(
                "CTITitle",
                parent=base["Title"],
                fontName=PDFExporter.FONT_BOLD,
                fontSize=22,
                leading=26,
                alignment=TA_CENTER,
                textColor=primary_color,
                spaceAfter=5,
            ),
            "subtitle": ParagraphStyle(
                "CTISubtitle",
                parent=base["Normal"],
                fontName=PDFExporter.FONT_BOLD,
                fontSize=11,
                leading=14,
                alignment=TA_CENTER,
                spaceAfter=8,
            ),
            "heading": ParagraphStyle(
                "CTIHeading",
                parent=base["Heading2"],
                fontName=PDFExporter.FONT_BOLD,
                fontSize=13,
                leading=16,
                textColor=primary_color,
                spaceBefore=8,
                spaceAfter=3,
            ),
            "body": ParagraphStyle(
                "CTIBody",
                parent=base["BodyText"],
                fontName=PDFExporter.FONT,
                fontSize=10,
                leading=14,
                alignment=TA_LEFT,
                spaceAfter=7,
            ),
            "bullet": ParagraphStyle(
                "CTIBullet",
                parent=base["BodyText"],
                fontName=PDFExporter.FONT,
                fontSize=10,
                leading=14,
                leftIndent=14,
                firstLineIndent=-8,
                spaceAfter=3,
            ),
            "table_label": ParagraphStyle(
                "CTITableLabel",
                parent=base["BodyText"],
                fontName=PDFExporter.FONT_BOLD,
                fontSize=9,
                leading=12,
            ),
            "table_value": ParagraphStyle(
                "CTITableValue",
                parent=base["BodyText"],
                fontName=PDFExporter.FONT,
                fontSize=9,
                leading=12,
            ),
            "source": ParagraphStyle(
                "CTISource",
                parent=base["BodyText"],
                fontName=PDFExporter.FONT,
                fontSize=9,
                leading=12,
                textColor=primary_color,
                spaceAfter=6,
            ),
            "generated": ParagraphStyle(
                "CTIGenerated",
                parent=base["BodyText"],
                fontName=PDFExporter.FONT,
                fontSize=8,
                leading=10,
                alignment=TA_RIGHT,
                textColor=secondary_color,
                spaceBefore=8,
            ),
            "banner": ParagraphStyle(
                "CTIBanner",
                parent=base["BodyText"],
                fontName=PDFExporter.FONT_BOLD,
                fontSize=9,
                leading=12,
                alignment=TA_CENTER,
                textColor=colors.white,
            ),
        }

    @staticmethod
    def _classification_banner(
        classification,
        primary_color,
        width,
        styles,
    ):
        table = Table(
            [[Paragraph(
                PDFExporter._escape(
                    str(classification or "ใช้ภายในองค์กร")
                ),
                styles["banner"],
            )]],
            colWidths=[width],
        )

        table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), primary_color),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ])
        )

        return table

    @staticmethod
    def _section_heading(text, width, primary_color, styles):
        table = Table(
            [[Paragraph(
                PDFExporter._escape(text),
                styles["heading"],
            )]],
            colWidths=[width],
        )

        table.setStyle(
            TableStyle([
                ("LINEBELOW", (0, 0), (-1, -1), 1, primary_color),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ])
        )

        return table

    @staticmethod
    def _threat_information(
        threat,
        width,
        primary_color,
        styles,
    ):
        heading = PDFExporter._section_heading(
            "ข้อมูลภัยคุกคาม",
            width,
            primary_color,
            styles,
        )

        rows = [
            ("หัวข้อ", threat.get("Title") or "ไม่ระบุ"),
            ("CVE", threat.get("CVE") or "ไม่ระบุ"),
            (
                "ระดับความรุนแรง",
                PDFExporter._localized_severity(threat.get("Severity")),
            ),
            ("CVSS", threat.get("CVSS") or "ไม่ระบุ"),
            (
                "ช่องโหว่ที่มีการโจมตีแล้ว",
                "ใช่" if threat.get("KEV") else "ไม่ใช่",
            ),
            ("แหล่งข้อมูล", threat.get("Source") or "ไม่ระบุ"),
            (
                "วันที่เผยแพร่",
                PDFExporter._format_date(
                    threat.get("PublishedDate")
                ),
            ),
        ]

        data = [
            [
                Paragraph(
                    PDFExporter._escape(label),
                    styles["table_label"],
                ),
                Paragraph(
                    PDFExporter._escape(value),
                    styles["table_value"],
                ),
            ]
            for label, value in rows
        ]

        table = Table(
            data,
            colWidths=[width * 0.31, width * 0.69],
        )

        table.setStyle(
            TableStyle([
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#BFC5CC"),
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    PDFExporter._lighten_color(primary_color),
                ),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ])
        )

        return [
            heading,
            Spacer(1, 0.1 * cm),
            table,
            Spacer(1, 0.15 * cm),
        ]

    @staticmethod
    def _content_section(
        heading,
        content,
        width,
        primary_color,
        styles,
    ):
        normalized = PDFExporter._normalize_multiline_text(content)

        paragraph = Paragraph(
            PDFExporter._escape(normalized).replace(
                "\n",
                "<br/>",
            ),
            styles["body"],
        )

        return [
            PDFExporter._section_heading(
                heading,
                width,
                primary_color,
                styles,
            ),
            Spacer(1, 0.08 * cm),
            paragraph,
        ]

    @staticmethod
    def _business_impact(
        business_impact,
        width,
        primary_color,
        styles,
    ):
        elements = [
            PDFExporter._section_heading(
                "ผลกระทบ",
                width,
                primary_color,
                styles,
            ),
            Spacer(1, 0.08 * cm),
        ]

        if business_impact:
            for item in business_impact:
                elements.append(
                    Paragraph(
                        "• "
                        + PDFExporter._escape(
                            PDFExporter._normalize_text(item)
                        ),
                        styles["bullet"],
                    )
                )
        else:
            elements.append(
                Paragraph(
                    "ไม่มีข้อมูลผลกระทบ",
                    styles["body"],
                )
            )

        return elements

    @staticmethod
    def _source_reference(
        threat,
        width,
        primary_color,
        styles,
    ):
        reference_url = (
            threat.get("ReferenceUrl")
            or "ไม่มีแหล่งอ้างอิง"
        )

        safe_reference = PDFExporter._escape(reference_url)

        if PDFExporter._is_valid_web_url(reference_url):
            source_content = (
                f'<link href="{safe_reference}">'
                f"{safe_reference}</link>"
            )
        else:
            source_content = safe_reference

        return [
            PDFExporter._section_heading(
                "แหล่งอ้างอิง",
                width,
                primary_color,
                styles,
            ),
            Spacer(1, 0.08 * cm),
            Paragraph(source_content, styles["source"]),
            Paragraph(
                (
                    "วันที่สร้างเอกสาร: "
                    f"{datetime.now().strftime('%d %b %Y')}"
                ),
                styles["generated"],
            ),
        ]

    @staticmethod
    def _draw_header_footer(
        canvas,
        doc,
        company_name,
        company_short_name,
        department,
        classification,
        company_logo,
        primary_color,
        secondary_color,
    ):
        canvas.saveState()

        page_width, page_height = doc.pagesize
        left_x = 2.2 * cm
        right_x = page_width - 2.2 * cm
        top_y = page_height - 1.15 * cm

        logo_path = PDFExporter._resolve_logo_path(company_logo)

        logo_drawn = False

        if logo_path:
            try:
                image = ImageReader(str(logo_path))
                image_width, image_height = image.getSize()

                max_width = 3.0 * cm
                max_height = 1.25 * cm

                scale = min(
                    max_width / image_width,
                    max_height / image_height,
                )

                draw_width = image_width * scale
                draw_height = image_height * scale

                canvas.drawImage(
                    image,
                    left_x,
                    top_y - draw_height,
                    width=draw_width,
                    height=draw_height,
                    preserveAspectRatio=True,
                    mask="auto",
                )
                logo_drawn = True
            except (OSError, ValueError):
                logo_drawn = False

        if not logo_drawn:
            canvas.setFillColor(primary_color)
            canvas.setFont(PDFExporter.FONT_BOLD, 18)
            canvas.drawString(
                left_x,
                top_y - 0.65 * cm,
                str(company_short_name or "SUNSTAR"),
            )

        canvas.setFillColor(primary_color)
        canvas.setFont(PDFExporter.FONT_BOLD, 11)
        canvas.drawRightString(
            right_x,
            top_y - 0.2 * cm,
            str(company_name or "Sunstar Chemical (Thailand) Co., Ltd."),
        )

        canvas.setFillColor(colors.black)
        canvas.setFont(PDFExporter.FONT, 9)
        canvas.drawRightString(
            right_x,
            top_y - 0.65 * cm,
            str(department or "Information Technology Department"),
        )

        header_line_y = page_height - 2.55 * cm
        canvas.setStrokeColor(primary_color)
        canvas.setLineWidth(1.4)
        canvas.line(left_x, header_line_y, right_x, header_line_y)

        footer_line_y = 2.0 * cm
        canvas.setStrokeColor(secondary_color)
        canvas.setLineWidth(0.7)
        canvas.line(left_x, footer_line_y, right_x, footer_line_y)

        canvas.setFillColor(secondary_color)
        canvas.setFont(PDFExporter.FONT, 8)

        canvas.drawString(
            left_x,
            1.5 * cm,
            str(company_name or "Sunstar Chemical (Thailand) Co., Ltd."),
        )

        canvas.drawCentredString(
            page_width / 2,
            1.5 * cm,
            str(classification or "ใช้ภายในองค์กร"),
        )

        canvas.drawRightString(
            right_x,
            1.5 * cm,
            f"หน้า {doc.page}",
        )

        canvas.drawCentredString(
            page_width / 2,
            1.1 * cm,
            f"สร้างโดย {department or 'Information Technology Department'}",
        )

        canvas.restoreState()

    @staticmethod
    def _resolve_logo_path(company_logo):
        if not company_logo:
            return None

        raw_path = str(company_logo).strip()

        if not raw_path:
            return None

        normalized_path = raw_path.replace("\\", "/")

        if normalized_path.startswith("/static/"):
            relative_path = normalized_path.removeprefix("/static/")
            candidate = (
                Path(current_app.static_folder)
                / relative_path
            )
        elif normalized_path.startswith("static/"):
            relative_path = normalized_path.removeprefix("static/")
            candidate = (
                Path(current_app.static_folder)
                / relative_path
            )
        else:
            candidate = Path(raw_path)

            if not candidate.is_absolute():
                candidate = (
                    Path(current_app.root_path)
                    / candidate
                )

        try:
            resolved = candidate.resolve()
        except OSError:
            return None

        return resolved if resolved.is_file() else None

    @staticmethod
    def _parse_hex_color(value, default_value):
        raw_value = str(value or "").strip().lstrip("#")

        if len(raw_value) != 6:
            raw_value = default_value

        try:
            int(raw_value, 16)
            return colors.HexColor(f"#{raw_value}")
        except (TypeError, ValueError):
            return colors.HexColor(f"#{default_value}")

    @staticmethod
    def _lighten_color(color):
        factor = 0.88

        return colors.Color(
            color.red + (1 - color.red) * factor,
            color.green + (1 - color.green) * factor,
            color.blue + (1 - color.blue) * factor,
        )

    @staticmethod
    def _normalize_text(value):
        return " ".join(str(value or "").split())

    @staticmethod
    def _normalize_multiline_text(value):
        lines = [
            PDFExporter._normalize_text(line)
            for line in str(value or "").splitlines()
        ]

        return "\n".join(
            line for line in lines if line
        )

    @staticmethod
    def _escape(value):
        return (
            str(value or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    @staticmethod
    def _format_date(value):
        if value is None:
            return "ไม่ระบุ"

        if hasattr(value, "strftime"):
            return value.strftime("%d %b %Y")

        raw_value = str(value).strip()
        try:
            return datetime.fromisoformat(
                raw_value.replace("Z", "+00:00")
            ).strftime("%d %b %Y")
        except ValueError:
            return raw_value.split(".")[0]

    @staticmethod
    def _is_valid_web_url(value):
        try:
            parsed = urlparse(str(value))

            return (
                parsed.scheme in {"http", "https"}
                and bool(parsed.netloc)
            )
        except ValueError:
            return False

    @staticmethod
    def _safe_filename(value):
        safe_value = value

        for character in [
            "/",
            "\\",
            ":",
            "*",
            "?",
            '"',
            "<",
            ">",
            "|",
        ]:
            safe_value = safe_value.replace(character, "-")

        return safe_value.strip() or "ไม่ระบุ"
