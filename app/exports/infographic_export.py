from __future__ import annotations

import re
from io import BytesIO
from typing import Any

from PIL import Image, ImageDraw, ImageFont


class InfographicExporter:
    WIDTH = 1240
    HEIGHT = 1754

    BG = "#F4F7FB"
    NAVY = "#173B64"
    BLUE = "#2C6CB0"
    LIGHT_BLUE = "#DCEBFA"
    RED = "#C93D3D"
    LIGHT_RED = "#FBE3E3"
    GREEN = "#2F7D4A"
    LIGHT_GREEN = "#E3F3E8"
    ORANGE = "#D97706"
    WHITE = "#FFFFFF"
    TEXT = "#1E293B"
    MUTED = "#64748B"
    BORDER = "#D8E1EA"

    @classmethod
    def _font(cls, size: int, bold: bool = False):
        candidates = (
            [
                r"C:\Windows\Fonts\LeelawUIb.ttf",
                r"C:\Windows\Fonts\tahomabd.ttf",
                r"C:\Windows\Fonts\arialbd.ttf",
            ]
            if bold
            else [
                r"C:\Windows\Fonts\LeelawUI.ttf",
                r"C:\Windows\Fonts\tahoma.ttf",
                r"C:\Windows\Fonts\arial.ttf",
            ]
        )
        for path in candidates:
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                pass
        return ImageFont.load_default()

    @staticmethod
    def _safe(value: Any, default: str = "-") -> str:
        if value is None:
            return default
        if isinstance(value, (list, tuple, set)):
            text = " • ".join(str(item).strip() for item in value if str(item).strip())
        else:
            text = str(value).strip()
        return text or default

    @classmethod
    def _slug(cls, value: str) -> str:
        value = re.sub(r"[^\w\- ]+", "", value, flags=re.UNICODE)
        value = re.sub(r"\s+", "_", value).strip("_")
        return value[:80] or "threat"

    @staticmethod
    def _text_width(draw, value, font):
        box = draw.textbbox((0, 0), value, font=font)
        return box[2] - box[0]

    @classmethod
    def _split_long_word(cls, draw, word, font, max_width):
        chunks, current = [], ""
        for character in word:
            candidate = current + character
            if current and cls._text_width(draw, candidate, font) > max_width:
                chunks.append(current)
                current = character
            else:
                current = candidate
        if current:
            chunks.append(current)
        return chunks

    @classmethod
    def _wrapped_lines(cls, draw, text, font, max_width):
        lines = []
        paragraphs = cls._safe(text, "").splitlines() or [""]
        for paragraph in paragraphs:
            current = ""
            for original_word in paragraph.split():
                words = (
                    cls._split_long_word(draw, original_word, font, max_width)
                    if cls._text_width(draw, original_word, font) > max_width
                    else [original_word]
                )
                for word in words:
                    candidate = word if not current else f"{current} {word}"
                    if cls._text_width(draw, candidate, font) <= max_width:
                        current = candidate
                    else:
                        if current:
                            lines.append(current)
                        current = word
            if current:
                lines.append(current)
                current = ""
        return lines

    @classmethod
    def _ellipsize(cls, draw, text, font, max_width):
        ellipsis = "…"
        value = text.rstrip()
        while value and cls._text_width(draw, value + ellipsis, font) > max_width:
            value = value[:-1].rstrip()
        return value + ellipsis

    @classmethod
    def _draw_wrapped(
        cls, draw, text, box, font, fill, line_spacing=10, max_lines=None
    ):
        x1, y1, x2, y2 = box
        max_width = x2 - x1
        lines = cls._wrapped_lines(draw, text, font, max_width)
        line_height = max(font.size, draw.textbbox((0, 0), "Ag", font=font)[3])
        height_limit = max(0, (y2 - y1 + line_spacing) // (line_height + line_spacing))
        line_limit = min(max_lines or len(lines), height_limit)
        clipped = len(lines) > line_limit
        lines = lines[:line_limit]
        if clipped and lines:
            lines[-1] = cls._ellipsize(draw, lines[-1], font, max_width)

        y = y1
        for line in lines:
            draw.text((x1, y), line, font=font, fill=fill)
            y += line_height + line_spacing
        return y

    @staticmethod
    def _box(draw, box, fill, outline=None, radius=26, width=2):
        draw.rounded_rectangle(
            box, radius=radius, fill=fill, outline=outline, width=width
        )

    @classmethod
    def _section(cls, draw, x, y, label, accent, font_size=32):
        draw.rounded_rectangle((x, y + 3, x + 16, y + 49), radius=8, fill=accent)
        draw.text((x + 31, y), label, font=cls._font(font_size, True), fill=cls.TEXT)

    @classmethod
    def _severity_style(cls, severity):
        value = severity.lower()
        if value in {"critical", "วิกฤต"}:
            return cls.RED, cls.LIGHT_RED
        if value in {"high", "สูง"}:
            return cls.ORANGE, "#FFF1D6"
        if value in {"medium", "ปานกลาง"}:
            return cls.BLUE, cls.LIGHT_BLUE
        if value in {"low", "ต่ำ"}:
            return cls.GREEN, cls.LIGHT_GREEN
        return cls.MUTED, "#E9EEF4"

    @classmethod
    def _draw_bullets(cls, draw, items, box, accent):
        x1, y1, x2, _ = box
        item_height = 108
        for index, item in enumerate(items[:3]):
            top = y1 + index * item_height
            draw.ellipse((x1, top + 8, x1 + 18, top + 26), fill=accent)
            cls._draw_wrapped(
                draw,
                cls._safe(item, ""),
                (x1 + 34, top, x2, top + 88),
                cls._font(24),
                cls.TEXT,
                line_spacing=7,
                max_lines=3,
            )

    @classmethod
    def generate(cls, threat: dict[str, Any], infographic_content: dict[str, Any]):
        image = Image.new("RGB", (cls.WIDTH, cls.HEIGHT), cls.BG)
        draw = ImageDraw.Draw(image)
        margin = 70
        right = cls.WIDTH - margin
        content_width = cls.WIDTH - (margin * 2)

        headline = cls._safe(
            infographic_content.get("headline"),
            "Cyber Security Alert",
        )
        actions = list(infographic_content.get("actions") or [])[:3]
        avoid = list(infographic_content.get("avoid") or [])[:3]

        draw.rectangle((0, 0, cls.WIDTH, 290), fill=cls.NAVY)
        draw.text(
            (margin, 42),
            "CYBER SECURITY AWARENESS",
            font=cls._font(31, True),
            fill=cls.LIGHT_BLUE,
        )
        cls._draw_wrapped(
            draw,
            headline,
            (margin, 94, right - 230, 218),
            cls._font(50, True),
            cls.WHITE,
            line_spacing=8,
            max_lines=2,
        )
        cls._draw_wrapped(
            draw,
            cls._safe(threat.get("Title"), "Security advisory"),
            (margin, 232, right - 20, 274),
            cls._font(22),
            cls.LIGHT_BLUE,
            line_spacing=4,
            max_lines=1,
        )

        severity = cls._safe(threat.get("Severity"), "Information")
        severity_color, severity_bg = cls._severity_style(severity)
        badge = (right - 205, 100, right, 169)
        cls._box(draw, badge, severity_bg, radius=22)
        cls._draw_wrapped(
            draw,
            severity.upper(),
            (badge[0] + 18, badge[1] + 18, badge[2] - 18, badge[3] - 10),
            cls._font(25, True),
            severity_color,
            max_lines=1,
        )

        meta_y = 315
        cls._box(draw, (margin, meta_y, right, meta_y + 105), cls.WHITE, cls.BORDER, 24)
        meta_font = cls._font(23)
        cls._draw_wrapped(
            draw,
            f"Source: {cls._safe(threat.get('Source'))}",
            (margin + 28, meta_y + 19, margin + 560, meta_y + 52),
            meta_font,
            cls.TEXT,
            max_lines=1,
        )
        cls._draw_wrapped(
            draw,
            f"Published: {cls._safe(threat.get('PublishedDate'))}",
            (margin + 28, meta_y + 58, margin + 560, meta_y + 91),
            meta_font,
            cls.MUTED,
            max_lines=1,
        )
        cls._draw_wrapped(
            draw,
            f"CVE: {cls._safe(threat.get('CVE'))}",
            (right - 430, meta_y + 19, right - 28, meta_y + 52),
            meta_font,
            cls.TEXT,
            max_lines=1,
        )
        cls._draw_wrapped(
            draw,
            f"CVSS: {cls._safe(threat.get('CVSS'))}",
            (right - 430, meta_y + 58, right - 28, meta_y + 91),
            meta_font,
            cls.MUTED,
            max_lines=1,
        )

        cls._section(draw, margin, 450, "เกิดอะไรขึ้น", cls.BLUE)
        happened_box = (margin, 510, right, 650)
        cls._box(draw, happened_box, cls.WHITE, cls.BORDER)
        cls._draw_wrapped(
            draw,
            infographic_content.get("what_happened"),
            (margin + 32, 538, right - 32, 628),
            cls._font(28),
            cls.TEXT,
            line_spacing=10,
            max_lines=2,
        )

        cls._section(draw, margin, 680, "เหตุใดจึงสำคัญ", cls.RED)
        matters_box = (margin, 740, right, 880)
        cls._box(draw, matters_box, cls.WHITE, cls.BORDER)
        cls._draw_wrapped(
            draw,
            infographic_content.get("why_it_matters"),
            (margin + 32, 768, right - 32, 858),
            cls._font(28),
            cls.TEXT,
            line_spacing=10,
            max_lines=3,
        )

        column_gap = 28
        column_width = (content_width - column_gap) // 2
        left_x = margin
        right_x = margin + column_width + column_gap
        cls._section(draw, left_x, 910, "สิ่งที่ควรทำ", cls.GREEN, 30)
        cls._section(draw, right_x, 910, "สิ่งที่ควรหลีกเลี่ยง", cls.RED, 30)
        left_box = (left_x, 970, left_x + column_width, 1340)
        right_box = (right_x, 970, right_x + column_width, 1340)
        cls._box(draw, left_box, cls.WHITE, cls.BORDER)
        cls._box(draw, right_box, cls.WHITE, cls.BORDER)
        cls._draw_bullets(
            draw,
            actions,
            (left_box[0] + 28, left_box[1] + 28, left_box[2] - 24, left_box[3]),
            cls.GREEN,
        )
        cls._draw_bullets(
            draw,
            avoid,
            (right_box[0] + 28, right_box[1] + 28, right_box[2] - 24, right_box[3]),
            cls.RED,
        )

        cls._section(draw, margin, 1370, "ติดต่อฝ่าย IT", cls.BLUE)
        contact_box = (margin, 1430, right, 1565)
        cls._box(draw, contact_box, cls.LIGHT_BLUE, radius=28)
        draw.ellipse((margin + 28, 1462, margin + 96, 1530), fill=cls.BLUE)
        draw.text(
            (margin + 62, 1496),
            "!",
            font=cls._font(42, True),
            fill=cls.WHITE,
            anchor="mm",
        )
        cls._draw_wrapped(
            draw,
            infographic_content.get("contact_it"),
            (margin + 125, 1455, right - 30, 1544),
            cls._font(27),
            cls.TEXT,
            line_spacing=8,
            max_lines=3,
        )

        reference_y = 1595
        draw.line((margin, reference_y, right, reference_y), fill=cls.BORDER, width=2)
        draw.text(
            (margin, reference_y + 18),
            "Reference:",
            font=cls._font(21, True),
            fill=cls.MUTED,
        )
        cls._draw_wrapped(
            draw,
            cls._safe(threat.get("ReferenceUrl"), "No reference provided"),
            (margin + 125, reference_y + 18, right, cls.HEIGHT - 34),
            cls._font(20),
            cls.MUTED,
            line_spacing=5,
            max_lines=3,
        )

        output = BytesIO()
        image.save(output, format="PNG", optimize=True)
        output.seek(0)
        filename = (
            f"infographic_{cls._safe(threat.get('ThreatId'), 'latest')}_"
            f"{cls._slug(headline)}.png"
        )
        return output, filename
