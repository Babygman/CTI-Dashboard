import unittest

from app.services.risk_assessment import RiskAssessmentService


class RiskAssessmentServiceTests(unittest.TestCase):
    @staticmethod
    def _impact(*assets, matched=True):
        return {
            "matched": matched,
            "catalog_product_id": 1 if matched else None,
            "product_name": "FortiGate",
            "affected_asset_count": len(assets),
            "affected_assets": list(assets),
        }

    def test_default_policy_full_risk_scores_100(self):
        impact = self._impact(
            {
                "asset_name": "FG200E",
                "critical": True,
                "environment": "Production",
            }
        )
        context = {
            "cvss_score": 9.8,
            "kev": True,
            "public_exploit": True,
        }

        result = RiskAssessmentService().assess(impact, context)

        self.assertEqual(result["overall_score"], 100)
        self.assertEqual(result["overall_level"], "Critical")
        self.assertEqual(
            result["asset_results"],
            [
                {
                    "asset_name": "FG200E",
                    "score": 100,
                    "level": "Critical",
                    "reasons": [
                        "Critical Asset",
                        "Production",
                        "KEV",
                        "CVSS 9.8",
                        "Public Exploit",
                    ],
                }
            ],
        )

    def test_cvss_high_band_and_medium_level(self):
        impact = self._impact(
            {
                "asset_name": "Application",
                "critical": False,
                "environment": "production",
            }
        )

        result = RiskAssessmentService().assess(
            impact,
            {
                "cvss_score": "7.5",
                "kev": False,
                "public_exploit": False,
            },
        )

        self.assertEqual(result["overall_score"], 45)
        self.assertEqual(result["overall_level"], "Medium")
        self.assertEqual(
            result["asset_results"][0]["reasons"],
            ["Production", "CVSS 7.5"],
        )

    def test_risk_levels_and_overall_uses_highest_asset(self):
        impact = self._impact(
            {
                "asset_name": "Low Asset",
                "critical": False,
                "environment": "DR",
            },
            {
                "asset_name": "High Asset",
                "critical": True,
                "environment": "DR",
            },
        )

        result = RiskAssessmentService().assess(
            impact,
            {
                "cvss_score": 5.0,
                "kev": True,
                "public_exploit": False,
            },
        )

        self.assertEqual(
            [asset["score"] for asset in result["asset_results"]],
            [40, 60],
        )
        self.assertEqual(
            [asset["level"] for asset in result["asset_results"]],
            ["Medium", "Medium"],
        )
        self.assertEqual(result["overall_score"], 60)
        self.assertEqual(result["overall_level"], "Medium")

    def test_unmatched_or_empty_impact_has_no_risk(self):
        unmatched = self._impact(
            {
                "asset_name": "Ignored",
                "critical": True,
                "environment": "Production",
            },
            matched=False,
        )
        empty = self._impact()

        unmatched_result = RiskAssessmentService().assess(
            unmatched,
            {"cvss_score": 10, "kev": True, "public_exploit": True},
        )
        empty_result = RiskAssessmentService().assess(
            empty,
            {"cvss_score": 10, "kev": True, "public_exploit": True},
        )

        expected = {
            "overall_score": 0,
            "overall_level": "Informational",
            "asset_results": [],
        }
        self.assertEqual(unmatched_result, expected)
        self.assertEqual(empty_result, expected)

    def test_policy_overrides_are_applied(self):
        service = RiskAssessmentService(
            {
                "asset_exists": 5,
                "critical_asset": 5,
                "production": 5,
            }
        )
        impact = self._impact(
            {
                "asset_name": "Custom Policy Asset",
                "critical": True,
                "environment": "Production",
            }
        )

        result = service.assess(
            impact,
            {"cvss_score": None, "kev": False, "public_exploit": False},
        )

        self.assertEqual(result["overall_score"], 15)
        self.assertEqual(result["overall_level"], "Informational")

    def test_approved_risk_level_boundaries(self):
        boundaries = (
            (0, "Informational"),
            (19, "Informational"),
            (20, "Low"),
            (39, "Low"),
            (40, "Medium"),
            (69, "Medium"),
            (70, "High"),
            (89, "High"),
            (90, "Critical"),
            (100, "Critical"),
        )

        for score, expected_level in boundaries:
            with self.subTest(score=score):
                self.assertEqual(
                    RiskAssessmentService._level(score),
                    expected_level,
                )

    def test_invalid_cvss_is_rejected(self):
        impact = self._impact(
            {
                "asset_name": "Asset",
                "critical": False,
                "environment": "DR",
            }
        )

        for value in ("invalid", -0.1, 10.1):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "cvss_score"):
                    RiskAssessmentService().assess(
                        impact,
                        {
                            "cvss_score": value,
                            "kev": False,
                            "public_exploit": False,
                        },
                    )

    def test_invalid_policy_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            RiskAssessmentService({"unknown": 10})
        with self.assertRaisesRegex(ValueError, "must not be negative"):
            RiskAssessmentService({"asset_exists": -1})


if __name__ == "__main__":
    unittest.main()
