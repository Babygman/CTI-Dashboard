import json
import unittest
from datetime import datetime, timedelta

from app import create_app
from app.collectors.normalizer import NormalizedItem
from app.collectors.service import _process_item
from app.extensions import db
from app.models.collection_run import CollectionRun
from app.models.source import Source
from app.models.threat import Threat
from app.models.threat_observation import ThreatObservation


class Config:
    TESTING = True
    SECRET_KEY = "canonical-threat-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CTI_CANONICAL_TITLE_SIMILARITY_THRESHOLD = 0.85
    CTI_CANONICAL_CANDIDATE_LIMIT = 50


class CanonicalThreatTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(Config)
        self.context = self.app.app_context()
        self.context.push()
        connection = db.engine.raw_connection()
        connection.create_function(
            "sysutcdatetime",
            0,
            lambda: datetime.utcnow().isoformat(" "),
        )
        connection.close()
        db.create_all()
        now = datetime.utcnow()
        self.sources = [
            Source(
                SourceName="NVD",
                SourceType="Nvd",
                Enabled=True,
                CollectionIntervalMinutes=60,
                TimeoutSeconds=30,
                CreatedAt=now,
                UpdatedAt=now,
            ),
            Source(
                SourceName="Microsoft MSRC",
                SourceType="Demo",
                Enabled=True,
                CollectionIntervalMinutes=60,
                TimeoutSeconds=30,
                CreatedAt=now,
                UpdatedAt=now,
            ),
        ]
        db.session.add_all(self.sources)
        db.session.flush()
        self.runs = []
        for source in self.sources:
            run = CollectionRun(
                SourceId=source.SourceId,
                StartedAt=now,
                Status="Running",
                ItemsFetched=0,
                ItemsCreated=0,
                ItemsUpdated=0,
                ItemsSkipped=0,
            )
            db.session.add(run)
            db.session.flush()
            self.runs.append(run)
            run.Status = "Success"
            run.FinishedAt = now
        db.session.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.context.pop()

    @staticmethod
    def item(
        external_id,
        title,
        source_name,
        *,
        cves=(),
        product="Edge",
    ):
        now = datetime.utcnow()
        return NormalizedItem(
            external_id=external_id,
            title=title,
            source_url=f"https://example.test/{external_id}",
            published_date=now,
            source_name=source_name,
            vendor_name="Microsoft",
            severity="Critical",
            cve_ids=tuple(cves),
            cvss=None,
            kev=False,
            summary=f"Observation for {title}",
            raw_content=json.dumps(
                {"external_id": external_id, "product": product}
            ),
            product=product,
        )

    def process(self, source_index, item):
        return _process_item(
            self.sources[source_index],
            self.runs[source_index].CollectionRunId,
            item,
        )

    def test_merge_by_cve_preserves_both_observations(self):
        self.process(
            0,
            self.item(
                "nvd-1",
                "Edge remote code execution",
                "NVD",
                cves=("CVE-2026-9001",),
            ),
        )
        self.process(
            1,
            self.item(
                "msrc-1",
                "Microsoft browser security update",
                "Microsoft MSRC",
                cves=("CVE-2026-9001",),
            ),
        )
        db.session.commit()

        self.assertEqual(db.session.query(Threat).count(), 1)
        observations = db.session.scalars(
            db.select(ThreatObservation).order_by(
                ThreatObservation.ObservationId
            )
        ).all()
        self.assertEqual(len(observations), 2)
        self.assertEqual(
            {row.SourceId for row in observations},
            {source.SourceId for source in self.sources},
        )
        self.assertEqual(observations[1].MatchMethod, "CVE")

    def test_merge_by_normalized_title(self):
        self.process(
            0,
            self.item(
                "nvd-title",
                "Microsoft Edge: Security Update",
                "NVD",
            ),
        )
        self.process(
            1,
            self.item(
                "msrc-title",
                "Microsoft Edge Security Update",
                "Microsoft MSRC",
            ),
        )
        db.session.commit()

        self.assertEqual(db.session.query(Threat).count(), 1)
        latest = db.session.scalar(
            db.select(ThreatObservation).where(
                ThreatObservation.ExternalId == "msrc-title"
            )
        )
        self.assertEqual(latest.MatchMethod, "NormalizedTitle")

    def test_same_title_does_not_merge_unrelated_products(self):
        self.process(
            0,
            self.item(
                "nvd-edge",
                "Critical security update",
                "NVD",
                product="Edge",
            ),
        )
        self.process(
            1,
            self.item(
                "msrc-windows",
                "Critical security update",
                "Microsoft MSRC",
                product="Windows",
            ),
        )
        db.session.commit()

        self.assertEqual(db.session.query(Threat).count(), 2)

    def test_observation_history_and_dashboard_canonical_count(self):
        first = self.item(
            "nvd-dashboard",
            "Edge vulnerability",
            "NVD",
            cves=("CVE-2026-9002",),
        )
        second = self.item(
            "msrc-dashboard",
            "Edge security advisory",
            "Microsoft MSRC",
            cves=("CVE-2026-9002",),
        )
        self.process(0, first)
        self.process(1, second)
        db.session.commit()
        threat = db.session.scalar(db.select(Threat))

        detail = self.client.get(f"/threats/{threat.ThreatId}")
        dashboard = self.client.get("/")
        self.assertEqual(db.session.query(Threat).count(), 1)
        self.assertIn(b"Source Observations", detail.data)
        self.assertIn(b"Published Timeline", detail.data)
        self.assertIn(b"NVD", detail.data)
        self.assertIn(b"Microsoft MSRC", detail.data)
        self.assertIn(b"Contributing Sources", dashboard.data)


if __name__ == "__main__":
    unittest.main()
