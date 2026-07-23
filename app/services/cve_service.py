import re
from datetime import datetime

from app.extensions import db
from app.models.cve import CVE
from app.models.threat_cve import ThreatCVE
from app.repositories import CVERepository


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def normalize_cve_code(value):
    code = str(value or "").strip().upper()
    return code if CVE_PATTERN.fullmatch(code) else None


class CVEPersistenceService:
    """Persist every normalized CVE while retaining Threat.CVE compatibility."""

    @staticmethod
    def sync_threat(threat, codes, source=None, observed_at=None):
        normalized = []
        for value in codes or ():
            code = normalize_cve_code(value)
            if code and code not in normalized:
                normalized.append(code)
        if not normalized:
            return []

        observed_at = observed_at or datetime.utcnow()
        existing_cves = {
            cve.CVECode: cve
            for cve in db.session.execute(
                db.select(CVE).where(CVE.CVECode.in_(normalized))
            ).scalars()
        }
        existing_links = {
            link.CVEId: link
            for link in threat.cve_links
            if link.CVEId is not None
        }
        persisted = []
        for position, code in enumerate(normalized):
            cve = existing_cves.get(code)
            if cve is None:
                cve = CVE(
                    CVECode=code,
                    Description=threat.Summary,
                    PublishedAt=threat.PublishedDate,
                    ModifiedAt=threat.ModifiedDate,
                    CVSSScore=threat.CVSS,
                    CVSSSeverity=threat.Severity,
                )
                db.session.add(cve)
                db.session.flush()
                existing_cves[code] = cve
            else:
                CVEPersistenceService._enrich(cve, threat)

            link = existing_links.get(cve.CVEId)
            if link is None:
                link = ThreatCVE(
                    threat=threat,
                    cve=cve,
                    IsPrimary=False,
                    Source=source,
                    FirstSeenAt=observed_at,
                    LastSeenAt=observed_at,
                )
                db.session.add(link)
                existing_links[cve.CVEId] = link
            else:
                link.LastSeenAt = max(link.LastSeenAt, observed_at)
                if source and not link.Source:
                    link.Source = source
            persisted.append(link)

        db.session.flush()
        primary_id = persisted[0].CVEId
        for link in threat.cve_links:
            link.IsPrimary = False
        db.session.flush()
        existing_links[primary_id].IsPrimary = True
        threat.CVE = normalized[0]
        return persisted

    @staticmethod
    def _enrich(cve, threat):
        mappings = (
            ("Description", threat.Summary),
            ("PublishedAt", threat.PublishedDate),
            ("ModifiedAt", threat.ModifiedDate),
            ("CVSSScore", threat.CVSS),
            ("CVSSSeverity", threat.Severity),
        )
        for field, value in mappings:
            if value is not None and getattr(cve, field) is None:
                setattr(cve, field, value)


class CVEDetailService:
    def __init__(self, repository=None):
        self.repository = repository or CVERepository()

    def get(self, cve_id):
        cve = self.repository.get(cve_id)
        if cve is None:
            return None
        threats = [link.threat for link in cve.threat_links]
        evidence = self.repository.related_evidence(cve.CVEId, cve.CVECode)
        actions = self.repository.related_actions(
            [threat.ThreatId for threat in threats]
        )
        assets = self._related_assets(threats, self.repository.all_assets())
        return {
            "cve": cve,
            "threats": threats,
            "evidence": evidence,
            "assets": assets,
            "actions": actions,
        }

    @staticmethod
    def _related_assets(threats, assets):
        results = {}
        for threat in threats:
            vendor = (
                threat.vendor.VendorName.casefold()
                if threat.vendor and threat.vendor.VendorName
                else ""
            )
            title = (threat.Title or "").casefold()
            for asset in assets:
                product = asset.catalog_product
                asset_vendor = (
                    (product.VendorName if product else asset.Vendor) or ""
                ).casefold()
                asset_product = (
                    (product.ProductName if product else asset.Product) or ""
                ).casefold()
                if vendor and asset_vendor == vendor and (
                    not asset_product or asset_product in title
                ):
                    results[asset.AssetId] = asset
        return list(results.values())
