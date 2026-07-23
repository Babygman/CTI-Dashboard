import json
import re

from app.repositories import (
    RemediationActionRepository,
    ThreatEvidenceRepository,
)

from .impact_analysis import ImpactAnalysisService
from .risk_assessment import RiskAssessmentService


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class ThreatDetailService:
    """Build the threat detail view model from canonical and source evidence."""

    def __init__(
        self,
        repository=None,
        impact_service=None,
        risk_service=None,
        action_repository=None,
    ):
        self.repository = repository or ThreatEvidenceRepository()
        self.impact_service = impact_service or ImpactAnalysisService()
        self.risk_service = risk_service or RiskAssessmentService()
        self.action_repository = (
            action_repository or RemediationActionRepository()
        )

    def get(self, threat_id):
        threat = self.repository.get_threat(threat_id)
        if threat is None:
            return None

        evidence_rows = self.repository.list_evidence(threat_id)
        evidence = [
            self._evidence_item(source_item, source, collection_run)
            for source_item, source, collection_run in evidence_rows
        ]
        observations = self._observations(threat, evidence)
        vendor_name = (
            threat.vendor.VendorName if threat.vendor else None
        )
        product_name = self._product_name(threat, evidence)

        self.impact_service.preload()
        impact = self.impact_service.analyze(
            vendor_name, product_name or threat.Title
        )
        risk = self.risk_service.assess(
            impact,
            {
                "cvss_score": threat.CVSS,
                "kev": bool(threat.KEV),
            },
        )

        return {
            "threat": threat,
            "summary": threat.Summary,
            "vendor_name": vendor_name,
            "product_name": (
                impact.get("product_name")
                if impact.get("matched")
                else product_name
            ),
            "cves": self._cves(threat, evidence),
            "last_updated": self._last_updated(threat, evidence),
            "impact": impact,
            "risk": risk,
            "affected_assets": self._affected_assets(impact, risk),
            "ai_summary": self._ai_summary(threat),
            "evidence": evidence,
            "observations": observations,
            "source_badges": sorted(
                {
                    row["source_name"]
                    for row in observations
                    if row["source_name"]
                }
            ),
            "published_timeline": sorted(
                observations,
                key=lambda row: (
                    row["published_date"] or row["observed_date"],
                    row["observation"].ObservationId,
                ),
            ),
            "history": self._history(evidence),
            "related_actions": self.action_repository.list_for_threat(
                threat_id
            ),
        }

    @staticmethod
    def _observations(threat, evidence):
        links = {}
        fallback_links = {}
        for item in evidence:
            source_item = item["source_item"]
            key = (source_item.SourceId, source_item.ExternalId)
            links[key] = source_item.SourceUrl
            fallback_links.setdefault(
                source_item.SourceId, source_item.SourceUrl
            )
        return [
            {
                "observation": observation,
                "source_name": (
                    observation.source.SourceName
                    if observation.source
                    else threat.Source or "Legacy"
                ),
                "published_date": observation.PublishedDate,
                "observed_date": observation.ObservedDate,
                "source_url": links.get(
                    (observation.SourceId, observation.ExternalId)
                )
                or fallback_links.get(observation.SourceId),
            }
            for observation in threat.observations
        ]

    @staticmethod
    def _evidence_item(source_item, source, collection_run):
        metadata = ThreatDetailService._json_object(
            source_item.NormalizedMetadata
        )
        raw_content = ThreatDetailService._json_object(
            source_item.RawContent
        )
        identifiers = []
        for label, value in (
            ("External ID", source_item.ExternalId),
            ("CVE", source_item.CVE),
            ("Content hash", source_item.ContentHash),
            ("Match method", source_item.MatchMethod),
        ):
            if value:
                identifiers.append({"label": label, "value": value})
        return {
            "source_item": source_item,
            "source": source,
            "collection_run": collection_run,
            "metadata": metadata,
            "raw_content": raw_content,
            "identifiers": identifiers,
        }

    @staticmethod
    def _json_object(value):
        if not value:
            return {}
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def _product_name(threat, evidence):
        for attribute in ("Product", "ProductName"):
            value = getattr(threat, attribute, None)
            if value and str(value).strip():
                return str(value).strip()

        candidates = {}
        for item in evidence:
            metadata_products = item["metadata"].get(
                "product_candidates"
            )
            if isinstance(metadata_products, list):
                for candidate in metadata_products:
                    text = str(candidate or "").strip()
                    if text:
                        candidates.setdefault(text.casefold(), text)
            raw_product = item["raw_content"].get("product")
            if raw_product:
                text = str(raw_product).strip()
                if text:
                    candidates.setdefault(text.casefold(), text)
        if len(candidates) == 1:
            return next(iter(candidates.values()))
        return None

    @staticmethod
    def _cves(threat, evidence):
        if threat.cve_links:
            return [link.cve for link in threat.cve_links]
        values = {}
        candidates = [threat.CVE]
        for item in evidence:
            source_item = item["source_item"]
            candidates.extend(
                (source_item.CVE, source_item.ExternalId)
            )
        for candidate in candidates:
            value = str(candidate or "").strip().upper()
            if CVE_PATTERN.match(value):
                values.setdefault(value, value)
        return sorted(values.values())

    @staticmethod
    def _last_updated(threat, evidence):
        dates = [
            date
            for date in (threat.ModifiedDate, threat.CreatedAt)
            if date is not None
        ]
        for item in evidence:
            source_item = item["source_item"]
            dates.extend(
                date
                for date in (
                    source_item.SourceModifiedDate,
                    source_item.LastSeenAt,
                )
                if date is not None
            )
        return max(dates) if dates else None

    @staticmethod
    def _affected_assets(impact, risk):
        risk_assets = risk.get("asset_results") or []
        rows = []
        for index, asset in enumerate(
            impact.get("affected_assets") or []
        ):
            risk_asset = (
                risk_assets[index] if index < len(risk_assets) else {}
            )
            rows.append(
                {
                    **asset,
                    "risk_score": risk_asset.get("score"),
                    "risk_level": risk_asset.get("level"),
                    "risk_reasons": list(
                        risk_asset.get("reasons") or []
                    ),
                }
            )
        return rows

    @staticmethod
    def _ai_summary(threat):
        for attribute in ("AISummary", "AiSummary", "ai_summary"):
            value = getattr(threat, attribute, None)
            if value and str(value).strip():
                return str(value).strip()
        return None

    @staticmethod
    def _history(evidence):
        if not evidence:
            return []
        events = []
        first = min(
            evidence,
            key=lambda item: item["source_item"].FirstSeenAt,
        )
        first_item = first["source_item"]
        events.append(
            {
                "occurred_at": first_item.FirstSeenAt,
                "event": "First imported",
                "source_name": first["source"].SourceName,
                "collection_run_id": (
                    first["collection_run"].CollectionRunId
                    if first["collection_run"]
                    else None
                ),
            }
        )
        for item in evidence:
            source_item = item["source_item"]
            if source_item.LastSeenAt > source_item.FirstSeenAt:
                events.append(
                    {
                        "occurred_at": source_item.LastSeenAt,
                        "event": "Evidence updated",
                        "source_name": item["source"].SourceName,
                        "collection_run_id": (
                            item["collection_run"].CollectionRunId
                            if item["collection_run"]
                            else None
                        ),
                    }
                )
        latest = max(
            evidence,
            key=lambda item: (
                item["collection_run"].StartedAt
                if item["collection_run"]
                else item["source_item"].LastSeenAt
            ),
        )
        latest_at = (
            latest["collection_run"].StartedAt
            if latest["collection_run"]
            else latest["source_item"].LastSeenAt
        )
        events.append(
            {
                "occurred_at": latest_at,
                "event": "Latest collection",
                "source_name": latest["source"].SourceName,
                "collection_run_id": (
                    latest["collection_run"].CollectionRunId
                    if latest["collection_run"]
                    else None
                ),
            }
        )
        return sorted(
            events,
            key=lambda event: (
                event["occurred_at"],
                event["event"],
            ),
        )
