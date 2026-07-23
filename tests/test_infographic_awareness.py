import unittest
from datetime import datetime
from io import BytesIO
from unittest.mock import patch

from PIL import Image, ImageDraw

from app import create_app
from app.exports.infographic_export import InfographicExporter
from app.exports.pdf_export import PDFExporter
from app.services.awareness_service import AwarenessGenerator


class InfographicTestConfig:
    TESTING = True
    SECRET_KEY = "infographic-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class InfographicAwarenessContentTests(unittest.TestCase):
    def test_executive_summary_does_not_render_none_for_missing_cvss(self):
        summary = AwarenessGenerator.executive_summary(
            {
                "Title": "Security advisory",
                "Severity": "High",
                "CVE": "CVE-2026-1000",
                "CVSS": None,
                "Source": "Vendor",
            }
        )

        self.assertIn("CVSS : ไม่ระบุ", summary)
        self.assertNotIn("None", summary)

    def test_supported_threat_types_are_classified(self):
        cases = (
            ({"Title": "Remote vulnerability", "CVE": "CVE-2026-1000"}, "vulnerability"),
            ({"Title": "July Security Update Advisory"}, "patch_advisory"),
            ({"Title": "Phishing campaign targeting employees"}, "phishing"),
            ({"Title": "New malware delivery campaign"}, "malware"),
            ({"Title": "Ransomware activity detected"}, "ransomware"),
            ({"Title": "General security notice"}, "general_advisory"),
        )

        for threat, expected_type in cases:
            with self.subTest(expected_type=expected_type):
                content = AwarenessGenerator.infographic_content(threat)
                self.assertEqual(content["threat_type"], expected_type)

    def test_content_contract_is_employee_focused(self):
        content = AwarenessGenerator.infographic_content(
            {
                "Title": "Credential phishing campaign",
                "Summary": "Messages imitate the help desk.",
            }
        )

        self.assertTrue(content["headline"])
        self.assertTrue(content["what_happened"])
        self.assertTrue(content["why_it_matters"])
        self.assertEqual(len(content["actions"]), 3)
        self.assertEqual(len(content["avoid"]), 3)
        self.assertIn("ฝ่าย IT", content["contact_it"])
        self.assertTrue(all(isinstance(item, str) for item in content["actions"]))
        self.assertTrue(all(isinstance(item, str) for item in content["avoid"]))

    def test_headlines_are_short_and_specific_to_the_threat(self):
        cases = (
            ({"Title": "Microsoft Edge security update"}, "อัปเดตความปลอดภัย Microsoft Edge"),
            ({"Title": "Windows vulnerability", "CVE": "CVE-2026-1000"}, "อัปเดตความปลอดภัย Windows"),
            ({"Title": "Critical vulnerability", "CVE": "CVE-2026-1001"}, "ประกาศอัปเดตความปลอดภัยเร่งด่วน"),
            ({"Title": "Phishing campaign targeting employees"}, "ระวังการหลอกลวงทางออนไลน์"),
            ({"Title": "Ransomware activity detected"}, "แจ้งเตือนภัยแรนซัมแวร์"),
            ({"Title": "New malware delivery campaign"}, "ตรวจพบความเสี่ยงจากมัลแวร์"),
            ({"Title": "General security notice"}, "ประกาศด้านความมั่นคงปลอดภัยไซเบอร์"),
        )

        for threat, expected_headline in cases:
            with self.subTest(expected_headline=expected_headline):
                content = AwarenessGenerator.infographic_content(threat)
                self.assertEqual(content["headline"], expected_headline)

    def test_known_vendor_or_product_is_used_in_relevant_headline(self):
        cases = (
            ({"Title": "Chrome vulnerability", "CVE": "CVE-2026-2000"}, "อัปเดตความปลอดภัย Google Chrome"),
            ({"Title": "Adobe patch advisory"}, "อัปเดตความปลอดภัย Adobe"),
            ({"Title": "Cisco security notice"}, "ประกาศความปลอดภัย Cisco"),
            ({"Title": "ESXi security update"}, "อัปเดตความปลอดภัย VMware"),
        )

        for threat, expected_headline in cases:
            with self.subTest(expected_headline=expected_headline):
                content = AwarenessGenerator.infographic_content(threat)
                self.assertEqual(content["headline"], expected_headline)

    def test_incident_explanation_uses_natural_employee_language(self):
        content = AwarenessGenerator.infographic_content(
            {
                "Title": "Microsoft Edge remote code execution vulnerability",
                "CVE": "CVE-2026-3000",
            }
        )

        self.assertIn("พบช่องโหว่ด้านความปลอดภัย", content["what_happened"])
        self.assertIn("Microsoft Edge", content["what_happened"])
        self.assertIn("CVE-2026-3000", content["what_happened"])
        for system_term in ("deployment", "remediation", "technical workarounds"):
            self.assertNotIn(system_term, str(content).lower())

    def test_long_source_title_is_bounded_in_generated_copy(self):
        content = AwarenessGenerator.infographic_content(
            {"Title": "Security advisory " + ("with a very long title " * 20)}
        )
        self.assertLessEqual(len(content["what_happened"]), 210)
        self.assertIn("…", content["what_happened"])


class InfographicExporterTests(unittest.TestCase):
    def setUp(self):
        self.threat = {
            "ThreatId": 42,
            "Title": "CVE vulnerability affecting an enterprise product",
            "Severity": "High",
            "CVE": "CVE-2026-1234",
            "CVSS": "8.8",
            "Source": "Security Advisory",
            "PublishedDate": "2026-07-23",
            "ReferenceUrl": "https://example.test/advisories/CVE-2026-1234",
        }
        self.content = AwarenessGenerator.infographic_content(self.threat)

    def test_png_keeps_required_dimensions(self):
        output, filename = InfographicExporter.generate(
            self.threat,
            self.content,
        )
        with Image.open(output) as image:
            self.assertEqual(image.format, "PNG")
            self.assertEqual(image.size, (1240, 1754))
        self.assertTrue(filename.endswith(".png"))

    def test_dates_remove_time_and_microseconds(self):
        published = datetime(2026, 7, 24, 12, 34, 56, 789123)
        self.assertEqual(
            InfographicExporter._format_date(published),
            "24 Jul 2026",
        )
        self.assertEqual(
            PDFExporter._format_date("2026-07-24 12:34:56.789123"),
            "24 Jul 2026",
        )

    def test_export_labels_localize_severity(self):
        self.assertEqual(InfographicExporter._localized_severity("High"), "สูง")
        self.assertEqual(PDFExporter._localized_severity("Critical"), "วิกฤต")

    def test_lists_are_not_stringified_with_python_syntax(self):
        rendered = InfographicExporter._safe(["First action", "Second action"])
        self.assertEqual(rendered, "First action • Second action")
        self.assertNotIn("[", rendered)
        self.assertNotIn("]", rendered)

    def test_long_unbroken_text_wraps_inside_requested_width(self):
        image = Image.new("RGB", (500, 200), "white")
        draw = ImageDraw.Draw(image)
        font = InfographicExporter._font(24)
        max_width = 180
        lines = InfographicExporter._wrapped_lines(
            draw,
            "https://example.test/" + ("unbroken" * 40),
            font,
            max_width,
        )
        self.assertGreater(len(lines), 1)
        self.assertTrue(
            all(InfographicExporter._text_width(draw, line, font) <= max_width for line in lines)
        )

    def test_incident_explanation_is_limited_to_two_rendered_lines(self):
        image = Image.new("RGB", (900, 300), "white")
        draw = ImageDraw.Draw(image)
        font = InfographicExporter._font(28)

        with patch.object(
            InfographicExporter,
            "_ellipsize",
            wraps=InfographicExporter._ellipsize,
        ) as ellipsize:
            InfographicExporter._draw_wrapped(
                draw,
                "A very long employee-facing incident explanation " * 20,
                (0, 0, 600, 200),
                font,
                "black",
                max_lines=2,
            )

        ellipsize.assert_called_once()


class InfographicRouteTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(InfographicTestConfig)
        self.client = self.app.test_client()

    def test_route_uses_infographic_specific_content(self):
        threat = {"ThreatId": 7, "Title": "Phishing campaign"}
        infographic_content = AwarenessGenerator.infographic_content(threat)

        with (
            patch("app.awareness.routes.get_threat", return_value=threat),
            patch(
                "app.awareness.routes.AwarenessGenerator.infographic_content",
                return_value=infographic_content,
            ) as content_generator,
            patch(
                "app.awareness.routes.InfographicExporter.generate",
                return_value=(BytesIO(b"png"), "awareness.png"),
            ) as exporter,
        ):
            response = self.client.get("/awareness/export/infographic/7")

        self.assertEqual(response.status_code, 200)
        content_generator.assert_called_once_with(threat)
        exporter.assert_called_once_with(
            threat=threat,
            infographic_content=infographic_content,
        )

    def test_existing_export_routes_remain_registered(self):
        rules = {str(rule) for rule in self.app.url_map.iter_rules()}
        self.assertIn("/awareness/export/word/<int:threat_id>", rules)
        self.assertIn("/awareness/export/pdf/<int:threat_id>", rules)
        self.assertIn("/awareness/export/ppt/<int:threat_id>", rules)
        self.assertIn("/awareness/export/infographic/<int:threat_id>", rules)


if __name__ == "__main__":
    unittest.main()
