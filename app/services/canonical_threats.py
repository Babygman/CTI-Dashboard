import json
import re
from dataclasses import dataclass
from difflib import SequenceMatcher

from sqlalchemy import func

from app.extensions import db
from app.models.cve import CVE
from app.models.source_item import SourceItem
from app.models.threat import Threat
from app.models.threat_cve import ThreatCVE
from app.models.vendor import Vendor


TITLE_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


def normalize_title(value):
    return " ".join(TITLE_TOKEN_PATTERN.findall((value or "").casefold()))


def normalize_product(value):
    return " ".join(TITLE_TOKEN_PATTERN.findall((value or "").casefold()))


@dataclass(frozen=True)
class CanonicalMatch:
    threat: Threat | None
    method: str
    confidence: float


class CanonicalThreatService:
    """Find a canonical threat using bounded, product-safe comparisons."""

    def __init__(self, similarity_threshold=0.88, candidate_limit=100):
        self.similarity_threshold = similarity_threshold
        self.candidate_limit = candidate_limit

    @classmethod
    def from_app_config(cls):
        from flask import current_app

        return cls(
            current_app.config.get(
                "CTI_CANONICAL_TITLE_SIMILARITY_THRESHOLD", 0.88
            ),
            current_app.config.get(
                "CTI_CANONICAL_CANDIDATE_LIMIT", 100
            ),
        )

    def find(self, item):
        cve_match = self._by_cve(item.cve_ids)
        if cve_match is not None:
            return CanonicalMatch(cve_match, "CVE", 1.0)

        candidates = self._bounded_candidates(item)
        if not candidates:
            return CanonicalMatch(None, "Created", 1.0)

        products = self._products_by_threat(
            [threat.ThreatId for threat in candidates]
        )
        item_product = normalize_product(item.product)
        normalized_item_title = normalize_title(item.title)
        scored = []
        for threat in candidates:
            candidate_products = products.get(threat.ThreatId, set())
            if (
                item_product
                and candidate_products
                and item_product not in candidate_products
            ):
                continue
            title_score = SequenceMatcher(
                None,
                normalized_item_title,
                normalize_title(threat.Title),
            ).ratio()
            product_match = bool(
                item_product and item_product in candidate_products
            )
            if title_score == 1.0:
                scored.append((1.0, "NormalizedTitle", threat))
            elif title_score >= self.similarity_threshold:
                scored.append((title_score, "TitleSimilarity", threat))
            elif product_match and title_score >= 0.45:
                scored.append((0.75, "Product", threat))

        if not scored:
            return CanonicalMatch(None, "Created", 1.0)
        scored.sort(
            key=lambda row: (-row[0], row[2].ThreatId)
        )
        confidence, method, threat = scored[0]
        return CanonicalMatch(threat, method, confidence)

    @staticmethod
    def _by_cve(cve_ids):
        if not cve_ids:
            return None
        return db.session.scalar(
            db.select(Threat)
            .outerjoin(ThreatCVE, ThreatCVE.ThreatId == Threat.ThreatId)
            .outerjoin(CVE, CVE.CVEId == ThreatCVE.CVEId)
            .where(
                db.or_(
                    func.upper(Threat.CVE).in_(cve_ids),
                    CVE.CVECode.in_(cve_ids),
                )
            )
            .order_by(Threat.ThreatId.asc())
            .limit(1)
        )

    def _bounded_candidates(self, item):
        statement = db.select(Threat)
        if item.vendor_name:
            vendor_ids = db.select(Vendor.VendorId).where(
                func.lower(Vendor.VendorName)
                == item.vendor_name.casefold()
            )
            statement = statement.where(Threat.VendorId.in_(vendor_ids))
        else:
            first_token = normalize_title(item.title).split(" ", 1)[0]
            if first_token:
                statement = statement.where(
                    func.lower(Threat.Title).like(f"{first_token}%")
                )
        return list(
            db.session.scalars(
                statement.order_by(Threat.ThreatId.desc()).limit(
                    self.candidate_limit
                )
            )
        )

    @staticmethod
    def _products_by_threat(threat_ids):
        if not threat_ids:
            return {}
        rows = db.session.execute(
            db.select(
                SourceItem.ThreatId,
                SourceItem.RawContent,
                SourceItem.NormalizedMetadata,
            )
            .where(SourceItem.ThreatId.in_(threat_ids))
        )
        products = {}
        for threat_id, raw_content, metadata_content in rows:
            for content in (raw_content, metadata_content):
                try:
                    payload = json.loads(content or "")
                except (TypeError, ValueError):
                    continue
                if not isinstance(payload, dict):
                    continue
                candidates = [payload.get("product")]
                metadata_products = payload.get("product_candidates")
                if isinstance(metadata_products, list):
                    candidates.extend(metadata_products)
                for candidate in candidates:
                    product = normalize_product(candidate)
                    if product:
                        products.setdefault(threat_id, set()).add(
                            product
                        )
        return products
