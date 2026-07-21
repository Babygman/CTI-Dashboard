from decimal import Decimal, InvalidOperation


DEFAULT_POLICY = {
    "asset_exists": 20,
    "critical_asset": 20,
    "production": 15,
    "kev": 20,
    "cvss_critical": 15,
    "cvss_high": 10,
    "public_exploit": 10,
}

LEVEL_THRESHOLDS = (
    (90, "Critical"),
    (70, "High"),
    (40, "Medium"),
    (20, "Low"),
)


class RiskAssessmentService:
    """Calculate business risk from an existing impact result."""

    def __init__(self, policy=None):
        overrides = policy or {}
        unknown_keys = set(overrides) - set(DEFAULT_POLICY)
        if unknown_keys:
            unknown = ", ".join(sorted(unknown_keys))
            raise ValueError(f"Unsupported risk policy keys: {unknown}")

        self.policy = {**DEFAULT_POLICY, **overrides}
        for key, value in self.policy.items():
            try:
                points = Decimal(str(value))
            except (InvalidOperation, ValueError):
                raise ValueError(
                    f"Risk policy value for {key} must be numeric."
                ) from None
            if points < 0:
                raise ValueError(
                    f"Risk policy value for {key} must not be negative."
                )

    def assess(self, impact_result, threat_context):
        cvss_score = self._cvss_score(
            (threat_context or {}).get("cvss_score")
        )
        kev = bool((threat_context or {}).get("kev", False))
        public_exploit = bool(
            (threat_context or {}).get("public_exploit", False)
        )

        affected_assets = []
        if impact_result.get("matched"):
            affected_assets = impact_result.get("affected_assets") or []

        asset_results = [
            self._assess_asset(
                asset,
                cvss_score=cvss_score,
                kev=kev,
                public_exploit=public_exploit,
            )
            for asset in affected_assets
        ]
        overall_score = max(
            (asset["score"] for asset in asset_results),
            default=0,
        )
        return {
            "overall_score": overall_score,
            "overall_level": self._level(overall_score),
            "asset_results": asset_results,
        }

    def _assess_asset(self, asset, *, cvss_score, kev, public_exploit):
        score = Decimal(str(self.policy["asset_exists"]))
        reasons = []

        if bool(asset.get("critical", False)):
            score += Decimal(str(self.policy["critical_asset"]))
            reasons.append("Critical Asset")

        environment = (asset.get("environment") or "").strip()
        if environment.casefold() == "production":
            score += Decimal(str(self.policy["production"]))
            reasons.append("Production")

        if kev:
            score += Decimal(str(self.policy["kev"]))
            reasons.append("KEV")

        if cvss_score is not None and cvss_score >= Decimal("9"):
            score += Decimal(str(self.policy["cvss_critical"]))
            reasons.append(f"CVSS {self._number(cvss_score)}")
        elif cvss_score is not None and cvss_score >= Decimal("7"):
            score += Decimal(str(self.policy["cvss_high"]))
            reasons.append(f"CVSS {self._number(cvss_score)}")

        if public_exploit:
            score += Decimal(str(self.policy["public_exploit"]))
            reasons.append("Public Exploit")

        score_value = self._number(score)
        return {
            "asset_name": asset.get("asset_name"),
            "score": score_value,
            "level": self._level(score_value),
            "reasons": reasons,
        }

    @staticmethod
    def _cvss_score(value):
        if value in (None, ""):
            return None
        try:
            score = Decimal(str(value))
        except (InvalidOperation, ValueError):
            raise ValueError(
                "cvss_score must be a number between 0.0 and 10.0."
            ) from None
        if score < 0 or score > 10:
            raise ValueError(
                "cvss_score must be a number between 0.0 and 10.0."
            )
        return score

    @staticmethod
    def _number(value):
        if value == value.to_integral_value():
            return int(value)
        return float(value)

    @staticmethod
    def _level(score):
        for threshold, level in LEVEL_THRESHOLDS:
            if score >= threshold:
                return level
        return "Informational"
