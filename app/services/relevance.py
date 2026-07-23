import re

from app.models.threat_assessment import ThreatAssessment


USER_THREATS = ("phishing", "scam", "credential", "social engineering", "fraud")


def normalize(value):
    return " ".join(re.findall(r"[a-z0-9]+", str(value or "").lower()))


def _tokens(value):
    return {token for token in normalize(value).split() if len(token) > 1}


def assess_item(item, asset):
    text = normalize(
        " ".join(
            str(getattr(item, field, "") or "")
            for field in ("Title", "Summary", "Vendor", "Product", "Source", "Recommendation")
        )
    )
    vendor = normalize(asset.Vendor)
    product = normalize(asset.Product or asset.AssetName)
    version = normalize(asset.Version)
    vendor_hit = bool(vendor and vendor in text)
    product_tokens = _tokens(product)
    product_hit = bool(product_tokens and product_tokens.issubset(_tokens(text)))
    # Product/model matches are decisive; vendor-only matches need review.
    if product_hit:
        status = "Affected" if not version or version in text else "Possibly Affected"
        reason = f"Matched asset {asset.AssetName} using product/model term '{product}'."
    elif vendor_hit:
        status = "Possibly Affected"
        reason = f"Vendor '{asset.Vendor}' matches, but product/version evidence is incomplete."
    else:
        status = "Not Affected"
        reason = f"No vendor or product terms matched asset {asset.AssetName}."
    return status, reason


def recommend(item, status=None):
    text = normalize(
        " ".join(
            str(getattr(item, field, "") or "")
            for field in ("Title", "Summary", "Recommendation", "Source")
        )
    )
    severity = normalize(getattr(item, "Severity", ""))
    if any(term in text for term in USER_THREATS):
        return "Need Awareness", "User-targeted phishing, scam, or credential risk."
    if status in {"Affected", "Possibly Affected"}:
        if getattr(item, "KEV", False) or severity in {"critical", "high"}:
            reason = "Matched company asset with critical/high severity"
            if getattr(item, "KEV", False):
                reason += " and known exploitation (CISA KEV)"
            return "Need Patch", reason + "."
        if any(term in text for term in ("configuration", "mitigation", "workaround")):
            return "Need Configuration Change", "Matched asset and advisory provides mitigation."
        return "Need Monitor", "Matched asset; monitor while validating version applicability."
    if status == "Needs Review":
        return "Need Monitor", "Insufficient product or version information."
    return "Ignore", "No matching company asset or user-targeted risk."


def build_assessments(threat, assets):
    results = []
    for asset in assets:
        status, reason = assess_item(threat, asset)
        if status == "Not Affected":
            continue
        action, action_reason = recommend(threat, status)
        results.append(
            ThreatAssessment(
                threat=threat,
                asset=asset,
                ImpactStatus=status,
                MatchReason=reason,
                RecommendationType=action,
                RecommendationReason=action_reason,
            )
        )
    return results


def news_relevance(news, assets):
    text = normalize(f"{news.Title} {news.Summary or ''} {news.ThreatType or ''}")
    if any(term in text for term in USER_THREATS):
        return True, "Relevant to all users because it is a phishing/scam risk."
    matches = [assess_item(news, asset) for asset in assets]
    relevant = any(status != "Not Affected" for status, _ in matches)
    reason = next((reason for status, reason in matches if status != "Not Affected"), "")
    return relevant, reason or "No company asset terms matched."
