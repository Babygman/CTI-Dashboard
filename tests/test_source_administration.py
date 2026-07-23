import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

from app import create_app
from app.extensions import db
from app.models.collection_run import CollectionRun
from app.models.source import Source


class SourceAdministrationTestConfig:
    TESTING = True
    SECRET_KEY = "source-administration-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class SourceAdministrationRouteTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(SourceAdministrationTestConfig)
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
        self.source = Source(
            SourceName="CISA KEV",
            SourceType="CisaKev",
            BaseUrl="https://www.cisa.gov",
            FeedUrl="https://example.test/kev.json",
            Enabled=True,
            CollectionIntervalMinutes=60,
            TimeoutSeconds=30,
            Priority=90,
            CreatedAt=now,
            UpdatedAt=now,
        )
        self.unsupported_source = Source(
            SourceName="Planned Vendor",
            SourceType="Planned",
            Enabled=False,
            CollectionIntervalMinutes=120,
            TimeoutSeconds=30,
            Priority=10,
            CreatedAt=now,
            UpdatedAt=now,
        )
        db.session.add_all([self.source, self.unsupported_source])
        db.session.flush()
        db.session.add_all(
            [
                self._run(
                    self.source.SourceId,
                    status="Failed",
                    started_at=now - timedelta(hours=3),
                    error="Network timeout",
                ),
                self._run(
                    self.source.SourceId,
                    status="Success",
                    started_at=now - timedelta(minutes=30),
                ),
            ]
        )
        db.session.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.context.pop()

    @staticmethod
    def _run(source_id, *, status, started_at, error=None):
        return CollectionRun(
            SourceId=source_id,
            StartedAt=started_at,
            FinishedAt=started_at + timedelta(minutes=1),
            Status=status,
            ItemsFetched=10,
            ItemsCreated=4,
            ItemsUpdated=2,
            ItemsSkipped=4,
            ErrorMessage=error,
            WorkerName="test-worker",
        )

    def test_source_list_displays_health_and_run_metrics(self):
        response = self.client.get("/sources/")

        self.assertEqual(response.status_code, 200)
        for expected in (
            b"Source Administration",
            b"CISA KEV",
            b"Healthy",
            b"Success",
            b"Network timeout",
            b"Planned Vendor",
            b"Disabled",
        ):
            self.assertIn(expected, response.data)

    def test_source_detail_displays_configuration_and_history(self):
        response = self.client.get(
            f"/sources/{self.source.SourceId}"
        )

        self.assertEqual(response.status_code, 200)
        for expected in (
            b"Collection History",
            b"Successful Runs",
            b"Failed Runs",
            b"Network timeout",
            b"test-worker",
            b"Manual Run",
        ):
            self.assertIn(expected, response.data)

    def test_enable_and_disable_source(self):
        disable_response = self.client.post(
            f"/sources/{self.source.SourceId}/disable"
        )
        db.session.refresh(self.source)
        self.assertEqual(disable_response.status_code, 302)
        self.assertFalse(self.source.Enabled)

        enable_response = self.client.post(
            f"/sources/{self.source.SourceId}/enable"
        )
        db.session.refresh(self.source)
        self.assertEqual(enable_response.status_code, 302)
        self.assertTrue(self.source.Enabled)

    def test_manual_run_reuses_collector_runner(self):
        result = SimpleNamespace(
            status="Success",
            fetched=10,
            created=4,
            updated=2,
            skipped=4,
            errors=[],
        )
        collector = object()
        with (
            patch(
                "app.sources.routes.SourceAdministrationService."
                "create_collector",
                return_value=collector,
            ),
            patch(
                "app.sources.routes.run_collector",
                return_value=result,
            ) as runner,
        ):
            response = self.client.post(
                f"/sources/{self.source.SourceId}/run"
            )

        self.assertEqual(response.status_code, 302)
        runner.assert_called_once_with(
            collector,
            self.source,
            worker_name="Manual Web Run",
            logger=self.app.logger,
        )

    def test_manual_run_rejects_unimplemented_source(self):
        with patch(
            "app.sources.routes.run_collector"
        ) as runner:
            response = self.client.post(
                f"/sources/{self.unsupported_source.SourceId}/run",
                follow_redirects=True,
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"No collector is implemented for source type Planned",
            response.data,
        )
        runner.assert_not_called()

    def test_manual_run_rejects_existing_running_collection(self):
        now = datetime.utcnow()
        db.session.add(
            CollectionRun(
                SourceId=self.source.SourceId,
                StartedAt=now,
                Status="Running",
                ItemsFetched=0,
                ItemsCreated=0,
                ItemsUpdated=0,
                ItemsSkipped=0,
                WorkerName="active-worker",
            )
        )
        db.session.commit()

        with patch(
            "app.sources.routes.run_collector"
        ) as runner:
            response = self.client.post(
                f"/sources/{self.source.SourceId}/run",
                follow_redirects=True,
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"already has a running collection", response.data)
        runner.assert_not_called()

    def test_source_routes_are_registered(self):
        rules = {str(rule) for rule in self.app.url_map.iter_rules()}
        self.assertIn("/sources/", rules)
        self.assertIn("/sources/<int:source_id>", rules)
        self.assertIn("/sources/<int:source_id>/enable", rules)
        self.assertIn("/sources/<int:source_id>/disable", rules)
        self.assertIn("/sources/<int:source_id>/run", rules)


if __name__ == "__main__":
    unittest.main()
