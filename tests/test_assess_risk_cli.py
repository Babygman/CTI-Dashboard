import unittest
from unittest.mock import patch

from app import create_app


class TestConfig:
    TESTING = True
    SECRET_KEY = "risk-cli-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class AssessRiskCliTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)

    @staticmethod
    def _impact_result():
        return {
            "matched": True,
            "catalog_product_id": 1,
            "product_name": "FortiGate",
            "affected_asset_count": 1,
            "affected_assets": [
                {
                    "asset_name": "FG200E",
                    "owner": "IT",
                    "environment": "Production",
                    "critical": True,
                    "status": "Active",
                    "location": "Bangkok",
                }
            ],
        }

    def test_full_risk_output(self):
        with patch(
            "app.services.risk_commands.ImpactAnalysisService"
        ) as impact_service:
            impact_service.return_value.analyze.return_value = (
                self._impact_result()
            )
            result = self.app.test_cli_runner().invoke(
                args=[
                    "assess-risk",
                    "--vendor",
                    "Fortinet",
                    "--product",
                    "FortiOS",
                    "--cvss",
                    "9.8",
                    "--kev",
                    "--public-exploit",
                ]
            )

        self.assertEqual(result.exit_code, 0, result.output)
        impact_service.return_value.analyze.assert_called_once_with(
            "Fortinet", "FortiOS"
        )
        for expected in (
            "Overall Risk\nCritical",
            "Score\n100",
            "Affected Assets",
            "FG200E",
            "Risk\nCritical",
            "Critical Asset",
            "Production",
            "KEV",
            "CVSS 9.8",
            "Public Exploit",
        ):
            self.assertIn(expected, result.output)

    def test_flags_are_optional_and_cvss_high_band_is_used(self):
        with patch(
            "app.services.risk_commands.ImpactAnalysisService"
        ) as impact_service:
            impact_service.return_value.analyze.return_value = (
                self._impact_result()
            )
            result = self.app.test_cli_runner().invoke(
                args=[
                    "assess-risk",
                    "--vendor",
                    "Fortinet",
                    "--product",
                    "FortiOS",
                    "--cvss",
                    "8.0",
                ]
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Overall Risk\nMedium", result.output)
        self.assertIn("Score\n65", result.output)
        self.assertNotIn("KEV", result.output)
        self.assertNotIn("Public Exploit", result.output)

    def test_no_affected_assets_output(self):
        impact = {
            "matched": False,
            "catalog_product_id": None,
            "product_name": "Unknown",
            "affected_asset_count": 0,
            "affected_assets": [],
        }
        with patch(
            "app.services.risk_commands.ImpactAnalysisService"
        ) as impact_service:
            impact_service.return_value.analyze.return_value = impact
            result = self.app.test_cli_runner().invoke(
                args=[
                    "assess-risk",
                    "--vendor",
                    "Unknown",
                    "--product",
                    "Unknown",
                    "--cvss",
                    "9.8",
                    "--kev",
                ]
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Overall Risk\nInformational", result.output)
        self.assertIn("Score\n0", result.output)
        self.assertIn("Affected Assets\nNone", result.output)

    def test_required_options_and_cvss_range(self):
        runner = self.app.test_cli_runner()

        missing_product = runner.invoke(
            args=["assess-risk", "--cvss", "9.8"]
        )
        missing_cvss = runner.invoke(
            args=["assess-risk", "--product", "FortiOS"]
        )
        invalid_cvss = runner.invoke(
            args=[
                "assess-risk",
                "--product",
                "FortiOS",
                "--cvss",
                "11",
            ]
        )

        self.assertEqual(missing_product.exit_code, 2)
        self.assertIn("Missing option '--product'", missing_product.output)
        self.assertEqual(missing_cvss.exit_code, 2)
        self.assertIn("Missing option '--cvss'", missing_cvss.output)
        self.assertEqual(invalid_cvss.exit_code, 2)
        self.assertIn("not in the range", invalid_cvss.output)


if __name__ == "__main__":
    unittest.main()
