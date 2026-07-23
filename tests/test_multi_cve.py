import unittest
from datetime import datetime

from app import create_app
from app.collectors.normalizer import NormalizedItem
from app.collectors.service import _process_item
from app.extensions import db
from app.models.asset import Asset
from app.models.catalog_product import CatalogProduct
from app.models.cve import CVE
from app.models.remediation_action import RemediationAction
from app.models.collection_run import CollectionRun
from app.models.source import Source
from app.models.threat import Threat
from app.models.vendor import Vendor
from app.services.cve_service import CVEPersistenceService, normalize_cve_code


class Config:
    TESTING = True
    SECRET_KEY = "multi-cve-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class MultiCVETests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(Config)
        self.context = self.app.app_context()
        self.context.push()
        connection = db.engine.raw_connection()
        connection.create_function(
            "sysutcdatetime", 0, lambda: datetime.utcnow().isoformat(" ")
        )
        connection.close()
        db.create_all()
        vendor = Vendor(VendorName="Microsoft", Enabled=True)
        db.session.add(vendor)
        db.session.flush()
        self.threat = Threat(
            Title="Microsoft Edge security issue",
            VendorId=vendor.VendorId,
            Source="NVD",
            Severity="Critical",
            CVE="CVE-2026-1001",
            CVSS=9.8,
            Summary="Multiple vulnerabilities affect Microsoft Edge.",
            CreatedAt=datetime.utcnow(),
        )
        db.session.add(self.threat)
        db.session.flush()
        CVEPersistenceService.sync_threat(
            self.threat,
            ["cve-2026-1001", "CVE-2026-1002"],
            source="NVD",
        )
        db.session.commit()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.context.pop()

    def test_normalization_and_invalid_values(self):
        self.assertEqual(normalize_cve_code(" cve-2026-1234 "), "CVE-2026-1234")
        self.assertIsNone(normalize_cve_code("not-a-cve"))

    def test_multiple_cves_primary_and_duplicate_prevention(self):
        CVEPersistenceService.sync_threat(
            self.threat,
            ["CVE-2026-1001", "cve-2026-1002", "CVE-2026-1002"],
            source="NVD",
        )
        db.session.commit()
        self.assertEqual(db.session.query(CVE).count(), 2)
        self.assertEqual(len(self.threat.cve_links), 2)
        self.assertEqual(self.threat.primary_cve_code, "CVE-2026-1001")
        self.assertEqual(self.threat.additional_cve_count, 1)
        self.assertEqual(sum(link.IsPrimary for link in self.threat.cve_links), 1)

    def test_shared_cve_across_threats(self):
        second = Threat(
            Title="Windows shares a vulnerability",
            CVE="CVE-2026-1002",
            CreatedAt=datetime.utcnow(),
        )
        db.session.add(second)
        db.session.flush()
        CVEPersistenceService.sync_threat(second, ["CVE-2026-1002"])
        db.session.commit()
        shared = db.session.scalar(
            db.select(CVE).where(CVE.CVECode == "CVE-2026-1002")
        )
        self.assertEqual(len(shared.threat_links), 2)
        self.assertEqual(db.session.query(CVE).count(), 2)

    def test_collector_persists_every_discovered_cve(self):
        source = Source(
            SourceName="Test Feed",
            SourceType="Demo",
            Enabled=True,
            CollectionIntervalMinutes=60,
            TimeoutSeconds=30,
            Priority=50,
            CreatedAt=datetime.utcnow(),
            UpdatedAt=datetime.utcnow(),
        )
        db.session.add(source)
        db.session.flush()
        run = CollectionRun(
            SourceId=source.SourceId,
            StartedAt=datetime.utcnow(),
            Status="Running",
            ItemsFetched=0,
            ItemsCreated=0,
            ItemsUpdated=0,
            ItemsSkipped=0,
        )
        db.session.add(run)
        db.session.flush()
        item = NormalizedItem(
            external_id="multi-cve-item",
            title="A distinct multi-CVE collector item",
            source_url="https://example.test/multi",
            published_date=datetime.utcnow(),
            source_name="Test Feed",
            vendor_name="Example Vendor",
            severity="High",
            cve_ids=("CVE-2026-2001", "CVE-2026-2002"),
            cvss=None,
            kev=False,
            summary="Collector multi-CVE test.",
            raw_content='{"cves":["CVE-2026-2001","CVE-2026-2002"]}',
        )
        self.assertEqual(_process_item(source, run.CollectionRunId, item), "created")
        db.session.commit()
        created = db.session.scalar(
            db.select(Threat).where(
                Threat.Title == "A distinct multi-CVE collector item"
            )
        )
        self.assertEqual(
            [link.cve.CVECode for link in created.cve_links],
            ["CVE-2026-2001", "CVE-2026-2002"],
        )

    def test_threat_detail_and_filter_use_normalized_cves(self):
        detail = self.client.get(f"/threats/{self.threat.ThreatId}")
        filtered = self.client.get("/threats", query_string={"q": "CVE-2026-1002"})
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"CVE-2026-1001", detail.data)
        self.assertIn(b"CVE-2026-1002", detail.data)
        self.assertIn(self.threat.Title.encode(), filtered.data)

    def test_cve_list_filters_and_detail_integrations(self):
        product = CatalogProduct(
            VendorName="Microsoft",
            ProductName="Edge",
            Active=True,
            CreatedAt=datetime.utcnow(),
            UpdatedAt=datetime.utcnow(),
        )
        db.session.add(product)
        db.session.flush()
        db.session.add(
            Asset(
                AssetName="Employee Laptop",
                CatalogProductId=product.CatalogProductId,
                Status="Active",
                CreatedAt=datetime.utcnow(),
                UpdatedAt=datetime.utcnow(),
            )
        )
        db.session.add(
            RemediationAction(
                ThreatId=self.threat.ThreatId,
                Title="Patch Edge",
                ActionType="Patch",
                Priority="Critical",
                Status="Open",
                ApprovalStatus="Not Required",
            )
        )
        db.session.commit()
        primary = self.threat.primary_cve
        listing = self.client.get(
            "/cves/",
            query_string={
                "q": "cve-2026-1001",
                "severity": "Critical",
                "cvss_min": "9",
                "cvss_max": "10",
            },
        )
        detail = self.client.get(f"/cves/{primary.CVEId}")
        self.assertEqual(listing.status_code, 200)
        self.assertIn(b"CVE-2026-1001", listing.data)
        self.assertIn(b"Employee Laptop", detail.data)
        self.assertIn(b"Patch Edge", detail.data)
        self.assertIn(self.threat.Title.encode(), detail.data)

    def test_dashboard_displays_primary_and_additional_count(self):
        db.session.add(
            RemediationAction(
                ThreatId=self.threat.ThreatId,
                Title="Investigate Edge",
                ActionType="Investigate",
                Priority="High",
                Status="Open",
                ApprovalStatus="Not Required",
            )
        )
        db.session.commit()
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CVE-2026-1001", response.data)
        self.assertIn(b"+1", response.data)


if __name__ == "__main__":
    unittest.main()
