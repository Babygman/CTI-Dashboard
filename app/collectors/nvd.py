import gzip
import io
import json
import logging
from collections.abc import Mapping
from urllib.parse import unquote

import requests

from .base import BaseCollector, CollectorError
from .normalizer import NormalizedItem, normalize_item
from .registry import collector_registry


NVD_MODIFIED_FEED_URL = (
    "https://nvd.nist.gov/feeds/json/cve/2.0/"
    "nvdcve-2.0-modified.json.gz"
)
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{}"
MAX_COMPRESSED_BYTES = 50 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024
LOGGER = logging.getLogger(__name__)


def _english_description(cve):
    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        return None
    for description in descriptions:
        if (
            isinstance(description, Mapping)
            and str(description.get("lang", "")).lower() == "en"
            and str(description.get("value", "")).strip()
        ):
            return str(description["value"]).strip()
    for description in descriptions:
        if isinstance(description, Mapping) and str(
            description.get("value", "")
        ).strip():
            return str(description["value"]).strip()
    return None


def _title(cve_id, description):
    compact = " ".join(description.split())
    prefix = f"{cve_id}: "
    available = 255 - len(prefix)
    if len(compact) > available:
        compact = compact[: available - 3].rstrip() + "..."
    return prefix + compact


def _cpe_parts(criteria):
    if not isinstance(criteria, str) or not criteria.startswith("cpe:2.3:"):
        return None, None
    parts = criteria.split(":")
    if len(parts) < 5:
        return None, None
    vendor = unquote(parts[3]).replace("\\_", "_").replace("_", " ")
    product = unquote(parts[4]).replace("\\_", "_").replace("_", " ")
    return vendor.strip() or None, product.strip() or None


def _vendor_product_candidates(cve):
    vendors = set()
    products = set()

    affected = cve.get("affected")
    if isinstance(affected, list):
        for contribution in affected:
            if not isinstance(contribution, Mapping):
                continue
            affected_data = contribution.get("affectedData")
            if not isinstance(affected_data, list):
                continue
            for item in affected_data:
                if not isinstance(item, Mapping):
                    continue
                vendor = str(item.get("vendor", "")).strip()
                product = str(item.get("product", "")).strip()
                if vendor and vendor not in {"*", "-"}:
                    vendors.add(vendor)
                if product and product not in {"*", "-"}:
                    products.add(product)

    def visit(value):
        if isinstance(value, Mapping):
            criteria = value.get("criteria")
            vendor, product = _cpe_parts(criteria)
            if vendor and vendor not in {"*", "-"}:
                vendors.add(vendor)
            if product and product not in {"*", "-"}:
                products.add(product)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(cve.get("configurations"))
    return sorted(vendors, key=str.casefold), sorted(products, key=str.casefold)


def _select_cvss(cve):
    metrics = cve.get("metrics")
    if not isinstance(metrics, Mapping):
        return None

    source_identifier = str(cve.get("sourceIdentifier", "")).casefold()
    versions = (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    )
    for key, version in versions:
        candidates = metrics.get(key)
        if not isinstance(candidates, list):
            continue

        def rank(metric):
            if not isinstance(metric, Mapping):
                return (3, "")
            metric_source = str(metric.get("source", "")).casefold()
            if source_identifier and metric_source == source_identifier:
                return (0, metric_source)
            if str(metric.get("type", "")).casefold() == "primary":
                return (1, metric_source)
            return (2, metric_source)

        for metric in sorted(candidates, key=rank):
            if not isinstance(metric, Mapping):
                continue
            data = metric.get("cvssData")
            if not isinstance(data, Mapping) or data.get("baseScore") is None:
                continue
            severity = data.get("baseSeverity") or metric.get("baseSeverity")
            return {
                "version": version,
                "score": data.get("baseScore"),
                "severity": str(severity).title() if severity else None,
                "vector": data.get("vectorString"),
                "source": metric.get("source"),
                "type": metric.get("type"),
            }
    return None


def _reference_urls(cve):
    references = cve.get("references")
    if not isinstance(references, list):
        return []
    urls = []
    for reference in references:
        if not isinstance(reference, Mapping):
            continue
        url = str(reference.get("url", "")).strip()
        if url and url not in urls:
            urls.append(url)
    return urls


@collector_registry.register
class NvdCollector(BaseCollector):
    """Collector for the official NVD CVE 2.0 modified JSON feed."""

    source_name = "NVD"
    source_type = "Nvd"

    def __init__(self, timeout_seconds=30, feed_url=None, session=None):
        super().__init__(timeout_seconds=timeout_seconds)
        self.feed_url = feed_url or NVD_MODIFIED_FEED_URL
        self.session = session or requests.Session()

    def fetch(self):
        last_error = None
        for attempt in range(1, 3):
            try:
                response = self.session.get(
                    self.feed_url,
                    timeout=self.timeout_seconds,
                    headers={
                        "Accept": "application/octet-stream, */*",
                        "User-Agent": "CTI-Dashboard/0.6 NVD-Collector",
                    },
                )
                response.raise_for_status()
                compressed = response.content
                if len(compressed) > MAX_COMPRESSED_BYTES:
                    raise ValueError("NVD feed exceeds compressed size limit")
                if compressed.startswith(b"\x1f\x8b"):
                    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as feed:
                        content = feed.read(MAX_UNCOMPRESSED_BYTES + 1)
                else:
                    content = compressed
                if len(content) > MAX_UNCOMPRESSED_BYTES:
                    raise ValueError("NVD feed exceeds uncompressed size limit")
                return json.loads(content.decode("utf-8"))
            except (
                requests.RequestException,
                OSError,
                UnicodeError,
                ValueError,
            ) as exc:
                last_error = exc
                if attempt == 1:
                    LOGGER.warning(
                        json.dumps(
                            {
                                "event": "nvd_fetch_retry",
                                "attempt": attempt,
                                "feed_url": self.feed_url,
                                "error_type": type(exc).__name__,
                                "error": str(exc),
                            }
                        )
                    )
        raise CollectorError(
            f"NVD download failed after two attempts: {last_error}"
        ) from last_error

    def parse(self, payload):
        if not isinstance(payload, Mapping):
            raise CollectorError("NVD response must be a JSON object")
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise CollectorError("NVD response is missing the vulnerabilities list")
        for wrapper in vulnerabilities:
            if isinstance(wrapper, Mapping):
                cve = wrapper.get("cve")
                if (
                    isinstance(cve, Mapping)
                    and str(cve.get("vulnStatus", "")).casefold() == "rejected"
                ):
                    continue
            yield wrapper

    def normalize(self, item) -> NormalizedItem:
        if not isinstance(item, Mapping) or not isinstance(item.get("cve"), Mapping):
            raise ValueError("NVD vulnerability must contain a CVE object")
        cve = item["cve"]
        cve_id = str(cve.get("id", "")).strip().upper()
        description = _english_description(cve)
        if not description:
            raise ValueError(f"NVD CVE description is required: {cve_id or 'unknown'}")

        vendors, products = _vendor_product_candidates(cve)
        vendor_name = (
            vendors[0]
            if len(vendors) == 1 and len(vendors[0]) <= 100
            else None
        )
        product = (
            products[0]
            if len(products) == 1 and len(products[0]) <= 500
            else None
        )
        cvss = _select_cvss(cve)
        reference_url = NVD_DETAIL_URL.format(cve_id)
        metadata = {
            "schema_version": 1,
            "source_identifier": cve.get("sourceIdentifier"),
            "vulnerability_status": cve.get("vulnStatus"),
            "cvss": cvss,
            "vendor_candidates": vendors,
            "product_candidates": products,
            "reference_urls": _reference_urls(cve),
            "weaknesses": cve.get("weaknesses") or [],
            "cisa_mirror": {
                "exploit_added": cve.get("cisaExploitAdd"),
                "action_due": cve.get("cisaActionDue"),
                "required_action": cve.get("cisaRequiredAction"),
                "vulnerability_name": cve.get("cisaVulnerabilityName"),
            },
        }
        severity = cvss.get("severity") if cvss else None
        if severity not in {"Critical", "High", "Medium", "Low"}:
            severity = None

        mapped_item = {
            "external_id": cve_id,
            "title": _title(cve_id, description),
            "source_url": reference_url,
            "published_date": cve.get("published"),
            "source_modified_date": cve.get("lastModified"),
            "source_name": self.source_name,
            "vendor_name": vendor_name,
            "product": product,
            "severity": severity,
            "cve_ids": [cve_id],
            "cvss": cvss.get("score") if cvss else None,
            "kev": False,
            "summary": description,
            "recommendation": None,
            "normalized_metadata": json.dumps(
                metadata, ensure_ascii=False, sort_keys=True, default=str
            ),
            "raw_content": json.dumps(
                dict(cve), ensure_ascii=False, sort_keys=True, default=str
            ),
        }
        return normalize_item(mapped_item, source_name=self.source_name)
