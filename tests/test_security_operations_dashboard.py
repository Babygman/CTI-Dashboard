import unittest
from unittest.mock import patch

from sqlalchemy import event

from app import create_app
from app.extensions import db


class DashboardTestConfig:
    TESTING = True
    SECRET_KEY = "security-operations-dashboard-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    OPERATIONS_DASHBOARD_THREAT_LIMIT = 10


class SecurityOperationsDashboardRouteTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(DashboardTestConfig)
        with self.app.app_context():
            db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()
            db.engine.dispose()

    @staticmethod
    def _operations(*, with_action=False):
        patch_actions = []
        if with_action:
            patch_actions.append(
                {
                    "threat_identifier": "CVE-2026-0001",
                    "asset_name": "FG200E",
                    "vendor": "Fortinet",
                    "product": "FortiGate",
                    "risk_level": "Critical",
                    "priority": "P1",
                    "recommendation": "Patch Immediately",
                    "target": "Today",
                    "reasons": ["Critical Asset", "KEV"],
                }
            )
        return {
            "summary": {
                "patch_immediately": len(patch_actions),
                "patch_this_week": 0,
                "review_and_schedule": 0,
                "notify_users": 0,
                "monitor": 0,
                "analysis_errors": 0,
            },
            "patch_immediately": patch_actions,
            "patch_this_week": [],
            "review_and_schedule": [],
            "communication_actions": [],
            "monitor": [],
            "analysis_errors": [],
        }

    def _get_dashboard(self, *, with_action=False):
        with patch(
            "app.dashboard.routes.OperationsDashboardService"
        ) as service_class:
            service_class.return_value.analyze.return_value = (
                self._operations(with_action=with_action)
            )
            response = self.client.get("/")
        return response

    def test_dashboard_route_renders_operational_sections(self):
        response = self._get_dashboard(with_action=True)

        self.assertEqual(response.status_code, 200)
        for text in (
            b"Security Operations",
            b"Patch Immediately",
            b"Patch This Week",
            b"Review and Schedule",
            b"User Awareness",
            b"Monitoring",
            b"CVE-2026-0001",
            b"FG200E",
        ):
            self.assertIn(text, response.data)

    def test_empty_states_render(self):
        response = self._get_dashboard()

        self.assertEqual(response.status_code, 200)
        for text in (
            b"No immediate patch actions.",
            b"No patch actions due this week.",
            b"No user notifications required.",
            b"No monitoring items.",
            b"No collection runs recorded.",
        ):
            self.assertIn(text, response.data)

    def test_existing_collection_metrics_still_render(self):
        response = self._get_dashboard()

        self.assertEqual(response.status_code, 200)
        for text in (
            b"Collection Health",
            b"Total Threats",
            b"Critical",
            b"High",
            b"KEV",
            b"Total Source Items",
            b"CISA Items",
            b"NVD Items",
            b"Multi-source Threats",
            b"Enabled Sources",
            b"Latest Collection Run",
            b"Threats by Severity",
            b"Top 10 Vendors",
        ):
            self.assertIn(text, response.data)

    def test_dashboard_request_executes_no_database_writes(self):
        statements = []

        def capture_statement(
            connection,
            cursor,
            statement,
            parameters,
            context,
            executemany,
        ):
            statements.append(statement.lstrip().upper())

        with self.app.app_context():
            event.listen(
                db.engine,
                "before_cursor_execute",
                capture_statement,
            )
            try:
                response = self._get_dashboard()
            finally:
                event.remove(
                    db.engine,
                    "before_cursor_execute",
                    capture_statement,
                )

        self.assertEqual(response.status_code, 200)
        write_prefixes = (
            "INSERT",
            "UPDATE",
            "DELETE",
            "MERGE",
            "CREATE",
            "ALTER",
            "DROP",
        )
        self.assertFalse(
            [
                statement
                for statement in statements
                if statement.startswith(write_prefixes)
            ]
        )


if __name__ == "__main__":
    unittest.main()
