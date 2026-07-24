import html
import json
import logging
import re
from collections.abc import Mapping
from xml.etree import ElementTree

import requests

from .base import BaseCollector, CollectorError
from .normalizer import NormalizedItem, normalize_item
from .registry import collector_registry
from .source_config import JPCERT_RSS_URL


LOGGER = logging.getLogger(__name__)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
HTML_TAG_PATTERN = re.compile(r"<[^>]+>")
NAMESPACES = {
    "rss": "http://purl.org/rss/1.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
}
VENDOR_TERMS = (
    ("Microsoft", ("microsoft", "マイクロソフト")),
    ("Fortinet", ("fortinet",)),
    ("Cisco", ("cisco",)),
    ("Adobe", ("adobe",)),
    ("VMware", ("vmware",)),
    ("Google", ("google",)),
    ("Palo Alto Networks", ("palo alto",)),
    ("Check Point", ("check point",)),
)


def _clean_text(value):
    if not value:
        return None
    without_tags = HTML_TAG_PATTERN.sub(" ", html.unescape(str(value)))
    result = " ".join(without_tags.split())
    return result or None


def _vendor_from_text(value):
    candidate = (value or "").casefold()
    for vendor, terms in VENDOR_TERMS:
        if any(term in candidate for term in terms):
            return vendor
    return None


@collector_registry.register
class JpcertCollector(BaseCollector):
    """Collector for the official JPCERT/CC RSS 1.0 advisory feed."""

    source_name = "JPCERT"
    source_type = "Jpcert"

    def __init__(
        self,
        timeout_seconds=30,
        feed_url=None,
        session=None,
    ):
        super().__init__(timeout_seconds=timeout_seconds)
        self.feed_url = feed_url or JPCERT_RSS_URL
        self.session = session or requests.Session()

    def fetch(self):
        last_error = None
        for attempt in range(1, 3):
            try:
                response = self.session.get(
                    self.feed_url,
                    timeout=self.timeout_seconds,
                    headers={
                        "Accept": (
                            "application/rdf+xml, application/xml, text/xml"
                        ),
                        "User-Agent": "CTI-Dashboard/3.1 JPCERT-Collector",
                    },
                )
                response.raise_for_status()
                return response.content
            except requests.RequestException as exc:
                last_error = exc
                if attempt == 1:
                    LOGGER.warning("JPCERT fetch retry: %s", exc)
        raise CollectorError(
            f"JPCERT download failed after two attempts: {last_error}"
        ) from last_error

    def parse(self, payload):
        if not isinstance(payload, (bytes, str)):
            raise CollectorError("JPCERT response must be XML")
        try:
            root = ElementTree.fromstring(payload)
        except ElementTree.ParseError as exc:
            raise CollectorError("JPCERT response is invalid XML") from exc

        items = root.findall("rss:item", NAMESPACES)
        if not items:
            raise CollectorError("JPCERT response contains no RSS items")
        for item in items:
            link = item.findtext("rss:link", namespaces=NAMESPACES)
            yield {
                "external_id": link
                or item.findtext("dc:identifier", namespaces=NAMESPACES),
                "title": item.findtext(
                    "rss:title",
                    namespaces=NAMESPACES,
                ),
                "source_url": link,
                "published_date": item.findtext(
                    "dc:date",
                    namespaces=NAMESPACES,
                ),
                "summary": item.findtext(
                    "rss:description",
                    namespaces=NAMESPACES,
                ),
                "raw_content": ElementTree.tostring(
                    item,
                    encoding="unicode",
                ),
            }

    def normalize(self, item) -> NormalizedItem:
        if not isinstance(item, Mapping):
            raise ValueError("JPCERT item must be a mapping")
        title = _clean_text(item.get("title"))
        source_url = _clean_text(item.get("source_url"))
        external_id = _clean_text(item.get("external_id")) or source_url
        if not title:
            raise ValueError("JPCERT title is required")
        if not external_id:
            raise ValueError("JPCERT item identifier is required")

        description = _clean_text(item.get("summary")) or title
        combined = f"{title} {description}"
        vendor = _vendor_from_text(combined)
        cve_ids = tuple(
            dict.fromkeys(
                match.upper() for match in CVE_PATTERN.findall(combined)
            )
        )
        summary_parts = [description]
        if vendor:
            summary_parts.append(f"Vendor: {vendor}.")
        mapped_item = {
            "external_id": external_id,
            "title": title[:255],
            "source_url": source_url,
            "published_date": item.get("published_date"),
            "source_name": self.source_name,
            "vendor_name": vendor,
            "product": vendor,
            "severity": None,
            "cve_ids": cve_ids,
            "cvss": None,
            "kev": False,
            "summary": " ".join(summary_parts),
            "recommendation": (
                "Review the JPCERT/CC advisory and apply the recommended "
                "vendor mitigations or security updates."
            ),
            "normalized_metadata": json.dumps(
                {
                    "schema_version": 1,
                    "feed_format": "RSS 1.0",
                    "cve_count": len(cve_ids),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            "raw_content": item.get("raw_content") or json.dumps(
                dict(item),
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            ),
        }
        return normalize_item(mapped_item, source_name=self.source_name)
