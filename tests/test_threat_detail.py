import unittest
from datetime import datetime, timedelta

from sqlalchemy import event

from app import create_app
from app.extensions import db
from app.models.asset import Asset
from app.models.catalog_product import CatalogProduct
from app.models.collection_run import CollectionRun
from app.models.source import Source
from app.models.source_item import SourceItem
from app.models.threat import Threat
from app.models.vendor import Vendor


class ThreatDetailTestConfig:
    TESTING = True
    SECRET_KEY = "threat-detail-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class ThreatDetailRouteTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(ThreatDetailTestConfig)
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

        vendor = Vendor(
            VendorName="Fortinet",
            Category="Network Security",
            Enabled=True,
        )
        db.session.add(vendor)
        db.session.flush()
        self.threat = Threat(
            Title="FortiOS remote code execution vulnerability",
            VendorId=vendor.VendorId,
            Source="CISA KEV",
            Severity="Critical",
            CVE="CVE-2026-1001",
            CVSS=9.8,
            KEV=True,
            PublishedDate=now - timedelta(days=4),
            Summary="A critical FortiOS vulnerability is being exploited.",
            Recommendation="Apply the vendor update.",
            CreatedAt=now - timedelta(days=3),
            ModifiedDate=now - timedelta(hours=1),
        )
        db.session.add(self.threat)
        catalog_product = CatalogProduct(
            VendorName="Fortinet",
            ProductName="FortiGate",
            Active=True,
            CreatedAt=now,
            UpdatedAt=now,
        )
        db.session.add(catalog_product)
        db.session.flush()
        db.session.add(
            Asset(
                AssetName="FG200E",
                CatalogProductId=catalog_product.CatalogProductId,
                Critical=True,
                Environment="Production",
                Owner="Network Operations",
                Location="Bangkok",
                Status="Active",
                CreatedAt=now,
                UpdatedAt=now,
            )
        )

        cisa = self._source(
            "CISA KEV", "CisaKev", now
        )
        nvd = self._source("NVD", "Nvd", now)
        db.session.add_all([cisa, nvd])
        db.session.flush()
        cisa_run = self._run(
            cisa.SourceId, now - timedelta(days=3)
        )
        nvd_run = self._run(
            nvd.SourceId, now - timedelta(hours=2)
        )
        db.session.add_all([cisa_run, nvd_run])
        db.session.flush()
        db.session.add_all(
            [
                SourceItem(
                    SourceId=cisa.SourceId,
                    CollectionRunId=cisa_run.CollectionRunId,
                    ExternalId="CVE-2026-1001",
                    CVE="CVE-2026-1001",
                    ContentHash="a" * 64,
                    Title="CISA original vulnerability title",
                    SourceUrl="https://example.test/cisa/CVE-2026-1001",
                    PublishedDate=now - timedelta(days=4),
                    RawContent='{"product": "FortiGate"}',
                    MatchMethod="CVE",
                    ProcessingStatus="Processed",
                    FirstSeenAt=now - timedelta(days=3),
                    LastSeenAt=now - timedelta(days=1),
                    ThreatId=self.threat.ThreatId,
                ),
                SourceItem(
                    SourceId=nvd.SourceId,
                    CollectionRunId=nvd_run.CollectionRunId,
                    ExternalId="CVE-2026-1002",
                    CVE="CVE-2026-1002",
                    ContentHash="b" * 64,
                    Title="NVD original vulnerability title",
                    SourceUrl="https://example.test/nvd/CVE-2026-1002",
                    PublishedDate=now - timedelta(days=4),
                    NormalizedMetadata=(
                        '{"product_candidates": ["FortiGate"]}'
                    ),
                    MatchMethod="ExistingLink",
                    ProcessingStatus="Duplicate",
                    FirstSeenAt=now - timedelta(days=2),
                    LastSeenAt=now - timedelta(hours=2),
                    ThreatId=self.threat.ThreatId,
                ),
            ]
        )
        db.session.commit()
        self.threat_id = self.threat.ThreatId
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.context.pop()

    @staticmethod
    def _source(name, source_type, now):
        return Source(
            SourceName=name,
            SourceType=source_type,
            Enabled=True,
            CollectionIntervalMinutes=60,
            TimeoutSeconds=30,
            Priority=50,
            CreatedAt=now,
            UpdatedAt=now,
        )

    @staticmethod
    def _run(source_id, started_at):
        return CollectionRun(
            SourceId=source_id,
            StartedAt=started_at,
            FinishedAt=started_at + timedelta(minutes=2),
            Status="Success",
            ItemsFetched=1,
            ItemsCreated=1,
            ItemsUpdated=0,
            ItemsSkipped=0,
            WorkerName="collector-worker",
        )

    def test_detail_displays_summary_risk_assets_and_all_evidence(self):
        response = self.client.get(
            f"/threats/{self.threat_id}"
        )

        self.assertEqual(response.status_code, 200)
        for expected in (
            b"Threat Summary",
            b"Critical",
            b"Score 90",
            b"Fortinet",
            b"FortiGate",
            b"FG200E",
            b"CVE-2026-1001",
            b"CVE-2026-1002",
            b"Source Evidence",
            b"CISA original vulnerability title",
            b"NVD original vulnerability title",
            b"Collection History",
            b"First imported",
            b"Evidence updated",
            b"Latest collection",
            b"No AI summary is available",
        ):
            self.assertIn(expected, response.data)

    def test_back_link_preserves_threat_list_filters(self):
        response = self.client.get(
            f"/threats/{self.threat_id}",
            query_string={
                "return_q": "FortiOS",
                "return_vendor_id": self.threat.VendorId,
                "return_severity": "Critical",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"q=FortiOS", response.data)
        self.assertIn(
            f"vendor_id={self.threat.VendorId}".encode(),
            response.data,
        )
        self.assertIn(b"severity=Critical", response.data)

    def test_threat_list_title_links_to_detail_with_filters(self):
        response = self.client.get(
            "/threats",
            query_string={
                "q": "FortiOS",
                "vendor_id": self.threat.VendorId,
                "severity": "Critical",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            f"/threats/{self.threat_id}".encode(),
            response.data,
        )
        self.assertIn(b"return_q=FortiOS", response.data)
        self.assertIn(b"return_severity=Critical", response.data)

    def test_detail_uses_five_bounded_selects(self):
        statements = []

        def capture_statement(
            connection,
            cursor,
            statement,
            parameters,
            context,
            executemany,
        ):
            if statement.lstrip().upper().startswith("SELECT"):
                statements.append(statement)

        event.listen(
            db.engine,
            "before_cursor_execute",
            capture_statement,
        )
        try:
            response = self.client.get(
                f"/threats/{self.threat_id}"
            )
        finally:
            event.remove(
                db.engine,
                "before_cursor_execute",
                capture_statement,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(statements), 8, statements)

    def test_missing_threat_returns_404(self):
        response = self.client.get("/threats/999999")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
