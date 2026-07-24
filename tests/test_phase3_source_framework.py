import unittest
from datetime import datetime

from app import create_app
from app.collectors import collector_registry
from app.collectors.jpcert import JpcertCollector
from app.collectors.microsoft_msrc import MicrosoftMsrcCollector
from app.collectors.service import run_collector
from app.extensions import db
from app.models.source import Source
from app.models.source_item import SourceItem
from app.models.threat import Threat
from app.models.threat_observation import ThreatObservation
from app.sources.service import SourceAdministrationService


JPCERT_SAMPLE = b"""<?xml version="1.0" encoding="utf-8"?>
<rdf:RDF
  xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
  xmlns="http://purl.org/rss/1.0/"
  xmlns:dc="http://purl.org/dc/elements/1.1/">
  <item rdf:about="https://www.jpcert.or.jp/at/2026/at260020.html">
    <title>Microsoft Releases July 2026 Security Updates</title>
    <link>https://www.jpcert.or.jp/at/2026/at260020.html</link>
    <dc:identifier>at260020</dc:identifier>
    <dc:date>2026-07-15T10:30:00+09:00</dc:date>
    <description>
      Microsoft security updates address CVE-2026-40001.
    </description>
  </item>
</rdf:RDF>
"""

MSRC_SAMPLE = {
    "value": [
        {
            "ID": "2026-Jul",
            "Alias": "2026-Jul",
            "DocumentTitle": "July 2026 Security Updates",
            "Severity": "Critical",
            "InitialReleaseDate": "2026-07-14T07:00:00Z",
            "CurrentReleaseDate": "2026-07-15T07:00:00Z",
            "CvrfUrl": (
                "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jul"
            ),
        }
    ]
}


class Config:
    TESTING = True
    SECRET_KEY = "phase3-source-framework-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class StaticCollectorMixin:
    payload = None

    def fetch(self):
        return self.payload


class StaticMsrcCollector(StaticCollectorMixin, MicrosoftMsrcCollector):
    payload = MSRC_SAMPLE


class StaticJpcertCollector(StaticCollectorMixin, JpcertCollector):
    payload = JPCERT_SAMPLE


class Phase3SourceFrameworkTests(unittest.TestCase):
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

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.context.pop()

    @staticmethod
    def add_source(name, source_type, feed_url):
        now = datetime.utcnow()
        source = Source(
            SourceName=name,
            SourceType=source_type,
            FeedUrl=feed_url,
            Enabled=True,
            CollectionIntervalMinutes=60,
            TimeoutSeconds=17,
            CreatedAt=now,
            UpdatedAt=now,
        )
        db.session.add(source)
        db.session.commit()
        return source

    def test_all_phase3_collectors_are_registered(self):
        self.assertTrue(
            {"cisakev", "nvd", "microsoftmsrc", "jpcert"}.issubset(
                collector_registry.registered_types()
            )
        )

    def test_collectors_are_created_from_persisted_source_configuration(self):
        source = self.add_source(
            "JPCERT",
            "Jpcert",
            "https://example.test/jpcert.rdf",
        )

        collector = SourceAdministrationService.create_collector(source)

        self.assertIsInstance(collector, JpcertCollector)
        self.assertEqual(collector.feed_url, source.FeedUrl)
        self.assertEqual(collector.timeout_seconds, 17)
        self.assertTrue(
            SourceAdministrationService.collector_available(source)
        )

    def test_msrc_normalizes_to_the_common_threat_shape(self):
        collector = MicrosoftMsrcCollector(current_year=2026)
        item = collector.normalize(next(collector.parse(MSRC_SAMPLE)))

        self.assertEqual(item.external_id, "2026-Jul")
        self.assertEqual(item.source_name, "Microsoft Security Response Center")
        self.assertEqual(item.vendor_name, "Microsoft")
        self.assertEqual(item.product, "Microsoft products")
        self.assertEqual(item.severity, "Critical")
        self.assertEqual(item.published_date, datetime(2026, 7, 14, 7))
        self.assertIn("/releaseNote/2026-Jul", item.source_url)

    def test_jpcert_normalizes_rss_and_extracts_source_vendor_and_cve(self):
        collector = JpcertCollector()
        item = collector.normalize(next(collector.parse(JPCERT_SAMPLE)))

        self.assertEqual(
            item.external_id,
            "https://www.jpcert.or.jp/at/2026/at260020.html",
        )
        self.assertEqual(item.source_name, "JPCERT")
        self.assertEqual(item.vendor_name, "Microsoft")
        self.assertEqual(item.cve_ids, ("CVE-2026-40001",))
        self.assertEqual(item.published_date, datetime(2026, 7, 15, 1, 30))

    def test_shared_pipeline_deduplicates_and_preserves_source_origin(self):
        source = self.add_source(
            "JPCERT",
            "Jpcert",
            "https://www.jpcert.or.jp/rss/jpcert.rdf",
        )
        collector = StaticJpcertCollector()

        first = run_collector(collector, source)
        second = run_collector(collector, source)

        self.assertEqual((first.created, first.skipped), (1, 0))
        self.assertEqual((second.created, second.skipped), (0, 1))
        self.assertEqual(db.session.query(Threat).count(), 1)
        self.assertEqual(db.session.query(SourceItem).count(), 1)
        source_item = db.session.scalar(db.select(SourceItem))
        self.assertEqual(source_item.SourceId, source.SourceId)
        self.assertEqual(source_item.source.SourceName, "JPCERT")
        observations = db.session.scalars(
            db.select(ThreatObservation)
        ).all()
        self.assertGreaterEqual(len(observations), 1)
        self.assertEqual(
            {observation.SourceId for observation in observations},
            {source.SourceId},
        )

    def test_msrc_records_are_visible_to_the_existing_news_page(self):
        source = self.add_source(
            "Microsoft Security Response Center",
            "MicrosoftMsrc",
            "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
        )
        result = run_collector(StaticMsrcCollector(), source)

        response = self.app.test_client().get("/news/")

        self.assertEqual(result.created, 1)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"July 2026 Security Updates", response.data)


if __name__ == "__main__":
    unittest.main()
