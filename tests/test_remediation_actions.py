import unittest
from datetime import date, datetime, timedelta
from unittest.mock import patch

from app import create_app
from app.extensions import db
from app.models.remediation_action import RemediationAction
from app.models.remediation_action_history import (
    RemediationActionHistory,
)
from app.models.threat import Threat


class RemediationActionTestConfig:
    TESTING = True
    SECRET_KEY = "remediation-action-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    OPERATIONS_DASHBOARD_THREAT_LIMIT = 10


class RemediationActionWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(RemediationActionTestConfig)
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        connection = db.engine.raw_connection()
        connection.create_function(
            "sysutcdatetime",
            0,
            lambda: datetime.utcnow().isoformat(" "),
        )
        connection.close()
        now = datetime.utcnow()
        self.threat = Threat(
            Title="Critical FortiOS vulnerability",
            Source="CISA KEV",
            Severity="Critical",
            CVE="CVE-2026-9001",
            CVSS=9.8,
            KEV=True,
            CreatedAt=now,
        )
        self.other_threat = Threat(
            Title="Windows vulnerability",
            Source="NVD",
            Severity="High",
            CVE="CVE-2026-9002",
            CVSS=8.8,
            KEV=False,
            CreatedAt=now,
        )
        db.session.add_all([self.threat, self.other_threat])
        db.session.commit()
        self.threat_id = self.threat.ThreatId
        self.other_threat_id = self.other_threat.ThreatId
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.context.pop()

    def _form(self, **overrides):
        values = {
            "threat_id": str(self.threat_id),
            "title": "Patch affected FortiGate systems",
            "description": "Deploy the approved FortiOS update.",
            "action_type": "Patch",
            "priority": "Critical",
            "status": "Open",
            "owner": "Network Operations",
            "due_date": (date.today() + timedelta(days=2)).isoformat(),
            "approval_status": "Approved",
            "ticket_reference": "INC-1001",
            "notes": "Coordinate the maintenance window.",
        }
        values.update(overrides)
        return values

    def _create_action(self, **overrides):
        response = self.client.post(
            "/actions/new",
            data=self._form(**overrides),
        )
        self.assertEqual(response.status_code, 302)
        return db.session.scalar(
            db.select(RemediationAction).order_by(
                RemediationAction.ActionId.desc()
            )
        )

    def test_create_action_and_threat_relationship(self):
        action = self._create_action()

        self.assertEqual(action.ThreatId, self.threat_id)
        self.assertEqual(action.threat.CVE, "CVE-2026-9001")
        self.assertEqual(action.Status, "Open")
        self.assertIsNone(action.CompletedAt)
        history = db.session.scalars(
            db.select(RemediationActionHistory).where(
                RemediationActionHistory.ActionId == action.ActionId
            )
        ).all()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].ChangeType, "Created")

    def test_edit_action_records_important_field_history(self):
        action = self._create_action()
        response = self.client.post(
            f"/actions/{action.ActionId}/edit",
            data=self._form(
                owner="Security Operations",
                priority="High",
                ticket_reference="CHG-2002",
            ),
        )

        self.assertEqual(response.status_code, 302)
        db.session.refresh(action)
        self.assertEqual(action.Owner, "Security Operations")
        self.assertEqual(action.Priority, "High")
        changed_fields = set(
            db.session.scalars(
                db.select(
                    RemediationActionHistory.FieldName
                ).where(
                    RemediationActionHistory.ActionId
                    == action.ActionId,
                    RemediationActionHistory.ChangeType
                    == "Field Changed",
                )
            ).all()
        )
        self.assertEqual(
            changed_fields,
            {"Owner", "Priority", "TicketReference"},
        )

    def test_complete_and_reopen_action(self):
        action = self._create_action()

        completed = self.client.post(
            f"/actions/{action.ActionId}/complete"
        )
        self.assertEqual(completed.status_code, 302)
        db.session.refresh(action)
        self.assertEqual(action.Status, "Completed")
        self.assertIsNotNone(action.CompletedAt)

        reopened = self.client.post(
            f"/actions/{action.ActionId}/reopen"
        )
        self.assertEqual(reopened.status_code, 302)
        db.session.refresh(action)
        self.assertEqual(action.Status, "Open")
        self.assertIsNone(action.CompletedAt)
        status_values = db.session.scalars(
            db.select(RemediationActionHistory.NewValue)
            .where(
                RemediationActionHistory.ActionId == action.ActionId,
                RemediationActionHistory.ChangeType
                == "Status Changed",
            )
            .order_by(RemediationActionHistory.HistoryId)
        ).all()
        self.assertEqual(status_values, ["Completed", "Open"])

    def test_overdue_calculation(self):
        action = self._create_action(
            due_date=(date.today() - timedelta(days=1)).isoformat()
        )
        self.assertTrue(action.is_overdue)

        action.Status = "Completed"
        self.assertFalse(action.is_overdue)

    def test_duplicate_action_is_rejected(self):
        self._create_action()
        response = self.client.post(
            "/actions/new",
            data=self._form(title="PATCH AFFECTED FORTIGATE SYSTEMS"),
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"already exists", response.data)
        count = db.session.scalar(
            db.select(db.func.count(RemediationAction.ActionId))
        )
        self.assertEqual(count, 1)

    def test_action_filters(self):
        self._create_action()
        self._create_action(
            threat_id=str(self.other_threat_id),
            title="Investigate Windows exposure",
            action_type="Investigate",
            priority="High",
            status="Blocked",
            owner="Endpoint Team",
            due_date=date.today().isoformat(),
        )

        response = self.client.get(
            "/actions/",
            query_string={
                "status": "Blocked",
                "priority": "High",
                "owner": "Endpoint",
                "due_date": date.today().isoformat(),
                "threat_id": self.other_threat_id,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Investigate Windows exposure", response.data)
        self.assertNotIn(
            b"Patch affected FortiGate systems",
            response.data,
        )

    def test_threat_detail_shows_related_actions(self):
        action = self._create_action()
        response = self.client.get(f"/threats/{self.threat_id}")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Related Remediation Actions", response.data)
        self.assertIn(action.Title.encode(), response.data)
        self.assertIn(b"Create Action", response.data)

    def test_dashboard_shows_open_actions(self):
        action = self._create_action()
        empty_operations = {
            "summary": {
                "patch_immediately": 0,
                "patch_this_week": 0,
                "review_and_schedule": 0,
                "notify_users": 0,
                "monitor": 0,
                "analysis_errors": 0,
            },
            "patch_immediately": [],
            "patch_this_week": [],
            "review_and_schedule": [],
            "communication_actions": [],
            "monitor": [],
            "analysis_errors": [],
        }
        with patch(
            "app.dashboard.routes.OperationsDashboardService"
        ) as operations:
            operations.return_value.analyze.return_value = (
                empty_operations
            )
            response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Open Remediation Actions", response.data)
        self.assertIn(action.Title.encode(), response.data)

    def test_action_routes_are_registered(self):
        rules = {str(rule) for rule in self.app.url_map.iter_rules()}
        for rule in (
            "/actions/",
            "/actions/new",
            "/actions/<int:action_id>",
            "/actions/<int:action_id>/edit",
            "/actions/<int:action_id>/status",
            "/actions/<int:action_id>/complete",
            "/actions/<int:action_id>/reopen",
        ):
            self.assertIn(rule, rules)


if __name__ == "__main__":
    unittest.main()
