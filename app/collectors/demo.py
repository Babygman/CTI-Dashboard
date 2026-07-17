from .base import BaseCollector
from .registry import collector_registry


@collector_registry.register
class DemoCollector(BaseCollector):
    """Local-only collector containing clearly labelled demonstration data."""

    source_name = "Local Demonstration Collector"
    source_type = "Demo"

    def fetch(self):
        first_item = {
            "external_id": "demo-2026-001",
            "title": "[DEMO] Critical remote access gateway vulnerability",
            "source_url": "https://demo.invalid/advisories/demo-2026-001",
            "published_date": "2026-01-15T09:00:00Z",
            "vendor_name": "Demo Network Security Vendor",
            "severity": "Critical",
            "cve_ids": ["CVE-2026-10001"],
            "cvss": "9.8",
            "kev": True,
            "summary": "Demonstration data: remote code execution example.",
        }
        second_item = {
            "external_id": "demo-2026-002",
            "title": "[DEMO] Backup management console privilege escalation",
            "source_url": "https://demo.invalid/advisories/demo-2026-002",
            "published_date": "2026-02-03T14:30:00Z",
            "vendor_name": "Demo Backup Software Vendor",
            "severity": "High",
            "cve_ids": ["CVE-2026-10002"],
            "cvss": 8.1,
            "kev": False,
            "summary": "Demonstration data: privilege escalation example.",
        }
        duplicate_item = {
            **first_item,
            # A different provider identifier with identical canonical content
            # exercises content-hash duplicate detection while preserving evidence.
            "external_id": "demo-2026-001-duplicate",
        }
        return [first_item, second_item, duplicate_item]
