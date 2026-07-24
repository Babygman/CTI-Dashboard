import json
import logging
from collections.abc import Mapping
from datetime import datetime, timezone

import requests

from .base import BaseCollector, CollectorError
from .normalizer import NormalizedItem, normalize_item
from .registry import collector_registry
from .source_config import MSRC_UPDATES_URL


LOGGER = logging.getLogger(__name__)
MSRC_RELEASE_NOTES_URL = (
    "https://msrc.microsoft.com/update-guide/en-us/releaseNote/{}"
)
SEVERITY_MAP = {
    "critical": "Critical",
    "important": "High",
    "moderate": "Medium",
    "low": "Low",
}


@collector_registry.register
class MicrosoftMsrcCollector(BaseCollector):
    """Collector for Microsoft Security Update Guide release summaries."""

    source_name = "Microsoft Security Response Center"
    source_type = "MicrosoftMsrc"

    def __init__(
        self,
        timeout_seconds=30,
        feed_url=None,
        session=None,
        current_year=None,
        years_to_fetch=2,
    ):
        super().__init__(timeout_seconds=timeout_seconds)
        self.feed_url = (feed_url or MSRC_UPDATES_URL).rstrip("/")
        self.session = session or requests.Session()
        self.current_year = current_year or datetime.now(timezone.utc).year
        self.years_to_fetch = max(int(years_to_fetch), 1)

    def fetch(self):
        updates = []
        for year in range(
            self.current_year - self.years_to_fetch + 1,
            self.current_year + 1,
        ):
            updates.extend(self._fetch_year(year))
        return {"value": updates}

    def _fetch_year(self, year):
        url = f"{self.feed_url}/{year}"
        last_error = None
        for attempt in range(1, 3):
            try:
                response = self.session.get(
                    url,
                    timeout=self.timeout_seconds,
                    headers={
                        "Accept": "application/json",
                        "User-Agent": "CTI-Dashboard/3.1 MSRC-Collector",
                    },
                )
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, Mapping):
                    raise ValueError("MSRC response must be a JSON object")
                values = payload.get("value")
                if not isinstance(values, list):
                    raise ValueError(
                        "MSRC response is missing the value list"
                    )
                return values
            except (requests.RequestException, ValueError) as exc:
                last_error = exc
                if attempt == 1:
                    LOGGER.warning(
                        "MSRC fetch retry for %s: %s",
                        url,
                        exc,
                    )
        raise CollectorError(
            f"MSRC download failed after two attempts for {year}: "
            f"{last_error}"
        ) from last_error

    def parse(self, payload):
        if not isinstance(payload, Mapping):
            raise CollectorError("MSRC response must be a JSON object")
        updates = payload.get("value")
        if not isinstance(updates, list):
            raise CollectorError("MSRC response is missing the value list")
        for update in updates:
            if isinstance(update, Mapping):
                yield update

    def normalize(self, item) -> NormalizedItem:
        if not isinstance(item, Mapping):
            raise ValueError("MSRC update must be a JSON object")
        external_id = str(item.get("ID") or item.get("Alias") or "").strip()
        title = str(item.get("DocumentTitle") or "").strip()
        if not external_id:
            raise ValueError("MSRC update ID is required")
        if not title:
            raise ValueError("MSRC document title is required")

        severity = SEVERITY_MAP.get(
            str(item.get("Severity") or "").strip().casefold()
        )
        cvrf_url = str(item.get("CvrfUrl") or "").strip() or None
        source_url = MSRC_RELEASE_NOTES_URL.format(external_id)
        summary = (
            f"Microsoft Security Response Center published {title}. "
            "Review the Security Update Guide for affected Microsoft "
            "products and applicable updates."
        )
        mapped_item = {
            "external_id": external_id,
            "title": title[:255],
            "source_url": source_url,
            "published_date": item.get("InitialReleaseDate"),
            "source_modified_date": item.get("CurrentReleaseDate"),
            "source_name": self.source_name,
            "vendor_name": "Microsoft",
            "product": "Microsoft products",
            "severity": severity,
            "cve_ids": (),
            "cvss": None,
            "kev": False,
            "summary": summary,
            "recommendation": (
                "Review the Microsoft Security Update Guide and apply "
                "updates that are applicable to company assets."
            ),
            "normalized_metadata": json.dumps(
                {
                    "schema_version": 1,
                    "document_id": external_id,
                    "cvrf_url": cvrf_url,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            "raw_content": json.dumps(
                dict(item),
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            ),
        }
        return normalize_item(mapped_item, source_name=self.source_name)
