import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from sqlalchemy.dialects import mssql

from app import create_app
from app.services.operations_dashboard import OperationsDashboardService


class TestConfig:
    TESTING = True
    SECRET_KEY = "operations-service-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    OPERATIONS_DASHBOARD_THREAT_LIMIT = 100


class OperationsDashboardServiceTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.impact = MagicMock()
        self.risk = MagicMock()
        self.decision = MagicMock()
        self.service = OperationsDashboardService(
            impact_service=self.impact,
            risk_service=self.risk,
            decision_engine=self.decision,
        )

    @staticmethod
    def _threat(threat_id=1, title="FortiOS"):
        return SimpleNamespace(
            ThreatId=threat_id,
            CVE=f"CVE-2026-{threat_id:04d}",
            Title=title,
            CVSS=9.8,
            KEV=True,
            vendor=SimpleNamespace(VendorName="Fortinet"),
        )

    def _configure_action(
        self,
        *,
        action_type,
        priority,
        recommendation,
        level,
        communication_actions=None,
    ):
        self.impact.analyze.return_value = {
            "matched": True,
            "catalog_product_id": 1,
            "product_name": "FortiGate",
            "affected_asset_count": 1,
            "affected_assets": [{"asset_name": "FG200E"}],
        }
        self.risk.assess.return_value = {
            "overall_score": 90,
            "overall_level": level,
            "asset_results": [
                {
                    "asset_name": "FG200E",
                    "score": 90,
                    "level": level,
                    "reasons": ["Critical Asset"],
                }
            ],
        }
        self.decision.recommend.return_value = {
            "overall_actions": [],
            "asset_actions": [
                {
                    "asset_name": "FG200E",
                    "action_type": action_type,
                    "priority": priority,
                    "recommendation": recommendation,
                    "target": "Target",
                    "reasons": ["Critical Asset"],
                }
            ],
            "communication_actions": communication_actions or [],
        }

    def _run_action(self, **action):
        self._configure_action(**action)
        return self.service.analyze([self._threat()], limit=1)

    def test_operations_results_are_grouped_correctly(self):
        actions = [
            ("REMEDIATE", "P1", "Patch Immediately", "Critical"),
            ("REMEDIATE", "P2", "Patch This Week", "High"),
            ("REMEDIATE", "P3", "Review and Schedule", "Medium"),
            ("MONITOR", "P4", "Monitor", "Low"),
            ("NO_ACTION", "P5", "No Action", "Informational"),
        ]
        self.impact.analyze.return_value = {
            "matched": True,
            "product_name": "FortiGate",
            "affected_assets": [
                {"asset_name": f"Asset {index}"}
                for index in range(len(actions))
            ],
        }
        self.risk.assess.return_value = {
            "overall_level": "Critical",
            "asset_results": [
                {
                    "asset_name": f"Asset {index}",
                    "level": values[3],
                }
                for index, values in enumerate(actions)
            ],
        }
        self.decision.recommend.return_value = {
            "overall_actions": [],
            "asset_actions": [
                {
                    "asset_name": f"Asset {index}",
                    "action_type": values[0],
                    "priority": values[1],
                    "recommendation": values[2],
                    "target": "Target",
                    "reasons": [],
                }
                for index, values in enumerate(actions)
            ],
            "communication_actions": [
                {
                    "action_type": "NOTIFY_USERS",
                    "priority": "P3",
                    "recommendation": "Notify Users",
                    "target": "As Soon As Practical",
                    "affected_user_group": "All Employees",
                    "reasons": ["Phishing campaign"],
                }
            ],
        }

        result = self.service.analyze([self._threat()], limit=1)

        self.assertEqual(
            result["summary"],
            {
                "patch_immediately": 1,
                "patch_this_week": 1,
                "review_and_schedule": 1,
                "notify_users": 1,
                "monitor": 1,
                "analysis_errors": 0,
            },
        )

    def test_p1_goes_to_patch_immediately(self):
        result = self._run_action(
            action_type="REMEDIATE",
            priority="P1",
            recommendation="Patch Immediately",
            level="Critical",
        )
        self.assertEqual(len(result["patch_immediately"]), 1)
        self.assertEqual(
            result["patch_immediately"][0]["risk_level"],
            "Critical",
        )

    def test_p2_goes_to_patch_this_week(self):
        result = self._run_action(
            action_type="REMEDIATE",
            priority="P2",
            recommendation="Patch This Week",
            level="High",
        )
        self.assertEqual(len(result["patch_this_week"]), 1)

    def test_p3_remediation_goes_to_review_and_schedule(self):
        result = self._run_action(
            action_type="REMEDIATE",
            priority="P3",
            recommendation="Review and Schedule",
            level="Medium",
        )
        self.assertEqual(len(result["review_and_schedule"]), 1)

    def test_notify_users_goes_to_user_awareness(self):
        result = self._run_action(
            action_type="NO_ACTION",
            priority="P5",
            recommendation="No Action",
            level="Informational",
            communication_actions=[
                {
                    "action_type": "NOTIFY_USERS",
                    "priority": "P3",
                    "recommendation": "Notify Users",
                    "target": "As Soon As Practical",
                    "affected_user_group": "All Employees",
                    "reasons": ["Phishing campaign"],
                }
            ],
        )
        self.assertEqual(len(result["communication_actions"]), 1)
        self.assertEqual(
            result["communication_actions"][0][
                "notification_reason"
            ],
            "Phishing campaign",
        )

    def test_monitor_goes_to_monitoring(self):
        result = self._run_action(
            action_type="MONITOR",
            priority="P4",
            recommendation="Monitor",
            level="Low",
        )
        self.assertEqual(len(result["monitor"]), 1)

    def test_no_action_is_excluded_from_operational_lists(self):
        result = self._run_action(
            action_type="NO_ACTION",
            priority="P5",
            recommendation="No Action",
            level="Informational",
        )
        self.assertEqual(result["patch_immediately"], [])
        self.assertEqual(result["patch_this_week"], [])
        self.assertEqual(result["review_and_schedule"], [])
        self.assertEqual(result["monitor"], [])

    def test_one_failed_threat_does_not_stop_remaining_analysis(self):
        self._configure_action(
            action_type="REMEDIATE",
            priority="P1",
            recommendation="Patch Immediately",
            level="Critical",
        )
        self.impact.analyze.side_effect = [
            RuntimeError("analysis failed"),
            self.impact.analyze.return_value,
        ]

        with self.assertLogs(
            "app.services.operations_dashboard", level="ERROR"
        ):
            result = self.service.analyze(
                [self._threat(1), self._threat(2)], limit=2
            )

        self.assertEqual(len(result["patch_immediately"]), 1)
        self.assertEqual(result["summary"]["analysis_errors"], 1)
        self.assertEqual(result["analysis_errors"][0]["threat_id"], 1)

    def test_analysis_error_count_is_correct(self):
        self.impact.analyze.side_effect = RuntimeError("failed")
        with self.assertLogs(
            "app.services.operations_dashboard", level="ERROR"
        ):
            result = self.service.analyze(
                [self._threat(1), self._threat(2)], limit=2
            )
        self.assertEqual(result["summary"]["analysis_errors"], 2)
        self.assertEqual(len(result["analysis_errors"]), 2)

    def test_threat_limit_is_enforced(self):
        self._configure_action(
            action_type="MONITOR",
            priority="P4",
            recommendation="Monitor",
            level="Low",
        )
        result = self.service.analyze(
            [self._threat(1), self._threat(2), self._threat(3)],
            limit=2,
        )
        self.assertEqual(self.impact.analyze.call_count, 2)
        self.assertEqual(result["summary"]["monitor"], 2)

    def test_configured_threat_limit_is_enforced(self):
        self._configure_action(
            action_type="MONITOR",
            priority="P4",
            recommendation="Monitor",
            level="Low",
        )
        self.app.config["OPERATIONS_DASHBOARD_THREAT_LIMIT"] = 2
        with self.app.app_context():
            result = self.service.analyze(
                [self._threat(1), self._threat(2), self._threat(3)]
            )
        self.assertEqual(self.impact.analyze.call_count, 2)
        self.assertEqual(result["summary"]["monitor"], 2)
    def test_deterministic_ordering_is_used(self):
        statement = self.service._recent_threat_query(25)
        sql = str(
            statement.compile(
                dialect=mssql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )
        self.assertIn("TOP 25", sql)
        self.assertIn(
            "ORDER BY [Threats].[CreatedAt] DESC, "
            "[Threats].[ThreatId] DESC",
            sql,
        )

    def test_injected_analysis_performs_no_database_calls(self):
        self._configure_action(
            action_type="MONITOR",
            priority="P4",
            recommendation="Monitor",
            level="Low",
        )
        with patch(
            "app.services.operations_dashboard.db.session"
        ) as session:
            self.service.analyze([self._threat()], limit=1)
        session.assert_not_called()
        self.assertEqual(session.method_calls, [])


if __name__ == "__main__":
    unittest.main()

