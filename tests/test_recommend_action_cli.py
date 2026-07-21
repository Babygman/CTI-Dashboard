import unittest
from unittest.mock import patch

from app import create_app


class TestConfig:
    TESTING = True
    SECRET_KEY = "decision-cli-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class RecommendActionCliTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.runner = self.app.test_cli_runner()

    @staticmethod
    def _impact(matched=True):
        assets = []
        if matched:
            assets.append(
                {
                    "asset_name": "FG200E",
                    "owner": "IT",
                    "environment": "Production",
                    "critical": True,
                    "status": "Active",
                    "location": "Bangkok",
                }
            )
        return {
            "matched": matched,
            "catalog_product_id": 1 if matched else None,
            "product_name": "FortiGate" if matched else "Outlook",
            "affected_asset_count": len(assets),
            "affected_assets": assets,
        }

    def _invoke_with_impact(self, args, *, matched=True):
        patcher = patch(
            "app.services.decision_commands.ImpactAnalysisService"
        )
        impact_service = patcher.start()
        self.addCleanup(patcher.stop)
        impact_service.return_value.analyze.return_value = self._impact(
            matched
        )
        result = self.runner.invoke(args=["recommend-action", *args])
        return result, impact_service

    def test_critical_remediation_only(self):
        result, impact_service = self._invoke_with_impact(
            [
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
        self.assertIn(
            "Overall Recommendation\nPatch Immediately", result.output
        )
        self.assertIn("Action Type\nREMEDIATE", result.output)
        self.assertIn("Priority\nP1", result.output)
        self.assertNotIn("Communication Recommendation", result.output)

    def test_user_notification_only(self):
        result, _ = self._invoke_with_impact(
            [
                "--vendor",
                "Microsoft",
                "--product",
                "Outlook",
                "--cvss",
                "8.8",
                "--notify-users",
                "--notification-reason",
                "Phishing campaign targeting Outlook users",
                "--affected-user-group",
                "All Employees",
            ],
            matched=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Action Type\nNO_ACTION", result.output)
        self.assertIn(
            "Communication Recommendation\nNotify Users",
            result.output,
        )
        self.assertIn("Action Type\nNOTIFY_USERS", result.output)
        self.assertIn("Priority\nP3", result.output)
        self.assertIn("Target\nAs Soon As Practical", result.output)
        self.assertIn(
            "Affected User Group\nAll Employees", result.output
        )
        self.assertIn(
            "Phishing campaign targeting Outlook users", result.output
        )

    def test_remediation_and_user_notification_together(self):
        result, _ = self._invoke_with_impact(
            [
                "--vendor",
                "Fortinet",
                "--product",
                "FortiOS",
                "--cvss",
                "9.8",
                "--kev",
                "--public-exploit",
                "--notify-users",
                "--notification-reason",
                "Users must avoid malicious links",
                "--affected-user-group",
                "All Employees",
            ]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Action Type\nREMEDIATE", result.output)
        self.assertIn("Action Type\nNOTIFY_USERS", result.output)
        self.assertIn("Patch Immediately", result.output)
        self.assertIn("Notify Users", result.output)

    def test_no_notification_context(self):
        result, _ = self._invoke_with_impact(
            ["--product", "FortiOS", "--cvss", "0"]
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("NOTIFY_USERS", result.output)
        self.assertNotIn("Communication Recommendation", result.output)

    def test_empty_notification_reason_validation_prevents_analysis(self):
        with patch(
            "app.services.decision_commands.ImpactAnalysisService"
        ) as impact_service:
            for args in (
                [
                    "recommend-action",
                    "--product",
                    "Outlook",
                    "--cvss",
                    "8.8",
                    "--notify-users",
                ],
                [
                    "recommend-action",
                    "--product",
                    "Outlook",
                    "--cvss",
                    "8.8",
                    "--notify-users",
                    "--notification-reason",
                    "   ",
                ],
            ):
                with self.subTest(args=args):
                    result = self.runner.invoke(args=args)
                    self.assertEqual(result.exit_code, 2, result.output)
                    self.assertIn(
                        "--notification-reason must not be empty",
                        result.output,
                    )
            impact_service.assert_not_called()

    def test_required_options_and_cvss_range(self):
        missing_product = self.runner.invoke(
            args=["recommend-action", "--cvss", "9.8"]
        )
        missing_cvss = self.runner.invoke(
            args=["recommend-action", "--product", "FortiOS"]
        )
        invalid_cvss = self.runner.invoke(
            args=[
                "recommend-action",
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
