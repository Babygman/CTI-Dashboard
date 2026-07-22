import unittest
from io import BytesIO
from unittest.mock import patch

from PIL import Image, ImageDraw

from app import create_app
from app.exports.infographic_export import InfographicExporter
from app.services.awareness_service import AwarenessGenerator


class InfographicTestConfig:
    TESTING = True
    SECRET_KEY = "infographic-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class InfographicAwarenessContentTests(unittest.TestCase):
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
        self.assertIn("IT", content["contact_it"])
        self.assertTrue(all(isinstance(item, str) for item in content["actions"]))
        self.assertTrue(all(isinstance(item, str) for item in content["avoid"]))

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
