import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import update
from sqlalchemy.dialects import mssql

from app import create_app
from app.extensions import db
from app.models.source import Source
from app.repositories.collection_lease_repository import (
    CollectionLeaseRepository,
)
from app.services.collection_lease import LeaseHeartbeat
from app.services.collection_worker import ScheduledCollectionWorker


class CollectionWorkerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        database_path = Path(self.tempdir.name) / "worker.db"

        class TestConfig:
            TESTING = True
            SECRET_KEY = "worker-test"
            SQLALCHEMY_DATABASE_URI = f"sqlite:///{database_path}"
            SQLALCHEMY_TRACK_MODIFICATIONS = False
            CTI_WORKER_POLL_INTERVAL_SECONDS = 1
            CTI_WORKER_LEASE_TIMEOUT_SECONDS = 2
            CTI_WORKER_HEARTBEAT_INTERVAL_SECONDS = 1
            CTI_WORKER_RETRY_INTERVAL_SECONDS = 5
            CTI_WORKER_BATCH_SIZE = 10

        self.app = create_app(TestConfig)
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        now = datetime.utcnow()
        source = Source(
            SourceName="Scheduled CISA",
            SourceType="CisaKev",
            FeedUrl="https://example.test/feed.json",
            Enabled=True,
            NextRunAt=now - timedelta(minutes=1),
            CollectionIntervalMinutes=60,
            TimeoutSeconds=30,
            CreatedAt=now,
            UpdatedAt=now,
        )
        db.session.add(source)
        db.session.commit()
        self.source_id = source.SourceId

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.context.pop()
        self.tempdir.cleanup()

    def _acquire(self, owner, now=None, timeout=30):
        return CollectionLeaseRepository.acquire(
            self.source_id,
            owner,
            now or datetime.utcnow(),
            timeout,
        )

    def test_acquire_and_active_lease_prevents_second_owner(self):
        self.assertTrue(self._acquire("worker-a"))
        self.assertFalse(self._acquire("worker-b"))

    def test_expired_lease_is_recovered(self):
        now = datetime.utcnow()
        source = db.session.get(Source, self.source_id)
        source.LeaseOwner = "stale-worker"
        source.LeaseExpiresAt = now - timedelta(seconds=1)
        source.UpdatedAt = now
        db.session.commit()

        self.assertTrue(self._acquire("replacement", now))
        db.session.refresh(source)
        self.assertEqual(source.LeaseOwner, "replacement")

    def test_not_yet_due_source_is_not_acquired(self):
        source = db.session.get(Source, self.source_id)
        now = datetime.utcnow()
        source.NextRunAt = now + timedelta(hours=1)
        source.UpdatedAt = now
        db.session.commit()

        self.assertFalse(self._acquire("early-worker"))

    def test_concurrent_workers_only_one_acquires(self):
        barrier = threading.Barrier(2)

        def compete(owner):
            with self.app.app_context():
                barrier.wait()
                return self._acquire(owner)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(
                executor.map(compete, ("worker-a", "worker-b"))
            )

        self.assertEqual(results.count(True), 1)

    def test_heartbeat_renews_expiration(self):
        self.assertTrue(self._acquire("worker-a", timeout=1))
        source = db.session.get(Source, self.source_id)
        original_expiration = source.LeaseExpiresAt

        heartbeat = LeaseHeartbeat(
            self.app, self.source_id, "worker-a", 0.05, 2
        )
        heartbeat.start()
        time.sleep(0.15)
        heartbeat.stop()

        db.session.expire_all()
        source = db.session.get(Source, self.source_id)
        self.assertGreater(source.LeaseExpiresAt, original_expiration)
        self.assertIsNotNone(source.LastHeartbeatAt)

    def test_release_schedules_next_run_and_clears_owner(self):
        self.assertTrue(self._acquire("worker-a"))
        next_run = datetime.utcnow() + timedelta(minutes=60)
        self.assertTrue(
            CollectionLeaseRepository.release(
                self.source_id, "worker-a", next_run
            )
        )
        source = db.session.get(Source, self.source_id)
        self.assertIsNone(source.LeaseOwner)
        self.assertIsNone(source.LeaseExpiresAt)
        self.assertEqual(source.NextRunAt, next_run)

    def test_two_worker_polls_dispatch_source_only_once(self):
        workers = [
            ScheduledCollectionWorker(self.app, owner="worker-a"),
            ScheduledCollectionWorker(self.app, owner="worker-b"),
        ]
        barrier = threading.Barrier(2)
        dispatches = []
        lock = threading.Lock()

        def collect(source_id):
            with lock:
                dispatches.append(source_id)

        def poll(worker):
            barrier.wait()
            with patch.object(worker, "_collect_leased_source", collect):
                return worker.run_once()

        with ThreadPoolExecutor(max_workers=2) as executor:
            counts = list(executor.map(poll, workers))

        self.assertEqual(sum(counts), 1)
        self.assertEqual(dispatches, [self.source_id])

    def test_atomic_update_compiles_for_sql_server(self):
        statement = (
            update(Source)
            .where(Source.SourceId == 1)
            .values(LeaseOwner="worker-a")
        )
        sql = str(statement.compile(dialect=mssql.dialect()))
        self.assertIn("UPDATE [Sources]", sql)
        self.assertIn("[LeaseOwner]", sql)


if __name__ == "__main__":
    unittest.main()
