import logging
import os
import socket
import threading
import uuid
from datetime import timedelta

from app.collectors.service import run_collector, utcnow
from app.extensions import db
from app.models.source import Source
from app.repositories.collection_lease_repository import (
    CollectionLeaseRepository,
)
from app.services.collection_lease import LeaseHeartbeat
from app.sources.service import SourceAdministrationService


class ScheduledCollectionWorker:
    """Poll due sources and execute the existing collector under a lease."""

    def __init__(self, app, owner=None):
        self.app = app
        self.owner = owner or (
            f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex}"
        )
        self.poll_interval = app.config[
            "CTI_WORKER_POLL_INTERVAL_SECONDS"
        ]
        self.lease_timeout = app.config[
            "CTI_WORKER_LEASE_TIMEOUT_SECONDS"
        ]
        self.heartbeat_interval = app.config[
            "CTI_WORKER_HEARTBEAT_INTERVAL_SECONDS"
        ]
        self.retry_interval = app.config[
            "CTI_WORKER_RETRY_INTERVAL_SECONDS"
        ]
        self.batch_size = app.config["CTI_WORKER_BATCH_SIZE"]
        if self.heartbeat_interval >= self.lease_timeout:
            raise ValueError(
                "CTI_WORKER_HEARTBEAT_INTERVAL_SECONDS must be less "
                "than CTI_WORKER_LEASE_TIMEOUT_SECONDS"
            )
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run_forever(self):
        self.app.logger.info(
            "scheduled collection worker started",
            extra={"lease_owner": self.owner},
        )
        while not self._stop_event.is_set():
            try:
                self.run_once()
            except Exception:
                self.app.logger.exception("collection worker polling failed")
            self._stop_event.wait(self.poll_interval)

    def run_once(self):
        with self.app.app_context():
            due_ids = CollectionLeaseRepository.due_source_ids(
                utcnow(), self.batch_size
            )

        processed = 0
        for source_id in due_ids:
            if self._stop_event.is_set():
                break
            if self._acquire(source_id):
                self._collect_leased_source(source_id)
                processed += 1
        return processed

    def _acquire(self, source_id):
        with self.app.app_context():
            return CollectionLeaseRepository.acquire(
                source_id,
                self.owner,
                utcnow(),
                self.lease_timeout,
            )

    def _collect_leased_source(self, source_id):
        heartbeat = LeaseHeartbeat(
            self.app,
            source_id,
            self.owner,
            self.heartbeat_interval,
            self.lease_timeout,
        )
        successful = False
        interval_minutes = 0
        heartbeat.start()
        try:
            with self.app.app_context():
                source = db.session.get(Source, source_id)
                if source is None:
                    return
                interval_minutes = source.CollectionIntervalMinutes
                if not SourceAdministrationService.collector_available(source):
                    self.app.logger.warning(
                        "enabled source has no collector",
                        extra={"source_id": source_id},
                    )
                    return
                collector = SourceAdministrationService.create_collector(source)
                result = run_collector(
                    collector,
                    source,
                    worker_name=self.owner,
                    logger=self.app.logger,
                )
                successful = result.status in {"Success", "Partial"}
        except Exception:
            self.app.logger.exception(
                "scheduled collection failed",
                extra={"source_id": source_id},
            )
        finally:
            heartbeat.stop()
            delay = (
                timedelta(minutes=interval_minutes)
                if successful
                else timedelta(seconds=self.retry_interval)
            )
            with self.app.app_context():
                CollectionLeaseRepository.release(
                    source_id,
                    self.owner,
                    utcnow() + delay,
                )
                db.session.remove()
