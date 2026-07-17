import json
import logging
from collections.abc import Mapping
from urllib.parse import urlencode

import requests

from .base import BaseCollector, CollectorError
from .normalizer import NormalizedItem, normalize_item
from .registry import collector_registry


CISA_KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CISA_KEV_CATALOG_URL = (
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
)
LOGGER = logging.getLogger(__name__)


def _required_text(item, field_name):
    value = item.get(field_name)
    if value is None or not str(value).strip():
        raise ValueError(f"CISA KEV field is required: {field_name}")
    return str(value).strip()


def _optional_text(item, field_name):
    value = item.get(field_name)
    if value is None:
        return None
    result = str(value).strip()
    return result or None


@collector_registry.register
class CisaKevCollector(BaseCollector):
    """Production collector for CISA's official KEV JSON catalog."""

    source_name = "CISA KEV"
    source_type = "CisaKev"

    def __init__(
        self,
        timeout_seconds=30,
        feed_url=None,
        session=None,
    ):
        super().__init__(timeout_seconds=timeout_seconds)
        self.feed_url = feed_url or CISA_KEV_FEED_URL
        self.session = session or requests.Session()

    def fetch(self):
        last_error = None
        for attempt in range(1, 3):
            try:
                response = self.session.get(
                    self.feed_url,
                    timeout=self.timeout_seconds,
                    headers={
                        "Accept": "application/json",
                        "User-Agent": "CTI-Dashboard/1.0 CISA-KEV-Collector",
                    },
                )
                response.raise_for_status()
                return response.json()
            except (requests.RequestException, ValueError) as exc:
                last_error = exc
                if attempt == 1:
                    LOGGER.warning(
                        json.dumps(
                            {
                                "event": "cisa_kev_fetch_retry",
                                "attempt": attempt,
                                "feed_url": self.feed_url,
                                "error_type": type(exc).__name__,
                                "error": str(exc),
                            }
                        )
                    )

        raise CollectorError(
            f"CISA KEV download failed after two attempts: {last_error}"
        ) from last_error

    def parse(self, payload):
        if not isinstance(payload, Mapping):
            raise CollectorError("CISA KEV response must be a JSON object")
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise CollectorError(
                "CISA KEV response is missing the vulnerabilities list"
            )
        yield from vulnerabilities

    def normalize(self, item) -> NormalizedItem:
        if not isinstance(item, Mapping):
            raise ValueError("CISA KEV vulnerability must be a JSON object")

        cve = _required_text(item, "cveID").upper()
        vendor = _required_text(item, "vendorProject")
        product = _required_text(item, "product")
        vulnerability_name = _required_text(item, "vulnerabilityName")
        date_added = _required_text(item, "dateAdded")
        short_description = _required_text(item, "shortDescription")
        required_action = _required_text(item, "requiredAction")
        due_date = _required_text(item, "dueDate")
        ransomware_use = _required_text(item, "knownRansomwareCampaignUse")
        notes = _optional_text(item, "notes")

        reference_url = (
            f"{CISA_KEV_CATALOG_URL}?"
            f"{urlencode({'search_api_fulltext': cve})}"
        )
        summary_parts = [
            f"Product: {product}.",
            short_description,
            f"Known ransomware campaign use: {ransomware_use}.",
        ]
        if notes:
            summary_parts.append(f"CISA notes: {notes}")
        recommendation = f"{required_action} CISA due date: {due_date}."

        mapped_item = {
            "external_id": cve,
            "title": vulnerability_name[:255],
            "source_url": reference_url,
            "published_date": date_added,
            "source_name": self.source_name,
            "vendor_name": vendor,
            "product": product,
            "severity": "Critical",
            "cve_ids": [cve],
            "cvss": None,
            "kev": True,
            "summary": "\n\n".join(summary_parts),
            "recommendation": recommendation,
            "known_ransomware_campaign_use": ransomware_use,
            "due_date": due_date,
            "notes": notes,
            "raw_content": json.dumps(
                dict(item), ensure_ascii=False, sort_keys=True, default=str
            ),
        }
        return normalize_item(mapped_item, source_name=self.source_name)
