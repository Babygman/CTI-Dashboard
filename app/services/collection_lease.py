import threading

from app.collectors.service import utcnow
from app.extensions import db
from app.repositories.collection_lease_repository import (
    CollectionLeaseRepository,
)


class LeaseHeartbeat:
    """Renew a lease in an independent Flask application context."""

    def __init__(
        self,
        app,
        source_id,
        owner,
        interval_seconds,
        lease_timeout_seconds,
    ):
        self.app = app
        self.source_id = source_id
        self.owner = owner
        self.interval_seconds = interval_seconds
        self.lease_timeout_seconds = lease_timeout_seconds
        self._stop_event = threading.Event()
        self._thread = None
        self.lease_lost = False

    def start(self):
        self._thread = threading.Thread(
            target=self._run,
            name=f"collection-heartbeat-{self.source_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval_seconds + 1)

    def _run(self):
        while not self._stop_event.wait(self.interval_seconds):
            try:
                with self.app.app_context():
                    renewed = CollectionLeaseRepository.renew(
                        self.source_id,
                        self.owner,
                        utcnow(),
                        self.lease_timeout_seconds,
                    )
                    db.session.remove()
                if not renewed:
                    self.lease_lost = True
                    return
            except Exception:
                self.app.logger.exception(
                    "collection lease heartbeat failed",
                    extra={"source_id": self.source_id},
                )
