import unittest

from app.services.decision_engine import DECISION_POLICY, DecisionEngine


class DecisionEngineTests(unittest.TestCase):
    @staticmethod
    def _risk_result(level="Critical", reasons=None):
        return {
            "overall_score": 100,
            "overall_level": level,
            "asset_results": [
                {
                    "asset_name": "FG200E",
                    "score": 100,
                    "level": level,
                    "reasons": list(reasons or []),
                }
            ],
        }

    def test_critical_remediation_only(self):
        result = DecisionEngine().recommend(
            self._risk_result("Critical", ["Critical Asset"])
        )

        self.assertEqual(
            result["overall_actions"],
            [
                {
                    "action_type": "REMEDIATE",
                    "priority": "P1",
                    "recommendation": "Patch Immediately",
                    "target": "Today",
                }
            ],
        )
        self.assertEqual(
            result["asset_actions"][0]["action_type"],
            "REMEDIATE",
        )
        self.assertEqual(result["communication_actions"], [])

    def test_user_notification_only(self):
        risk_result = {
            "overall_score": 0,
            "overall_level": "Informational",
            "asset_results": [],
        }
        result = DecisionEngine().recommend(
            risk_result,
            {
                "requires_user_notification": True,
                "notification_reason": "Phishing campaign",
                "affected_user_group": "All Employees",
            },
        )

        self.assertEqual(
            result["overall_actions"][0]["action_type"],
            "NO_ACTION",
        )
        self.assertEqual(result["asset_actions"], [])
        self.assertEqual(
            result["communication_actions"],
            [
                {
                    "action_type": "NOTIFY_USERS",
                    "priority": "P3",
                    "recommendation": "Notify Users",
                    "target": "As Soon As Practical",
                    "affected_user_group": "All Employees",
                    "reasons": ["Phishing campaign"],
                }
            ],
        )

    def test_remediation_and_user_notification_together(self):
        result = DecisionEngine().recommend(
            self._risk_result("High", ["Production", "CVSS 8.8"]),
            {
                "requires_user_notification": True,
                "notification_reason": "Active phishing campaign",
                "affected_user_group": "Outlook Users",
            },
        )

        self.assertEqual(
            result["overall_actions"][0]["action_type"],
            "REMEDIATE",
        )
        self.assertEqual(
            result["asset_actions"][0]["action_type"],
            "REMEDIATE",
        )
        self.assertEqual(
            result["communication_actions"][0]["action_type"],
            "NOTIFY_USERS",
        )

    def test_no_notification_context_is_backward_compatible(self):
        result = DecisionEngine().recommend(
            self._risk_result("Low", ["Asset Exists"])
        )

        self.assertEqual(
            set(result),
            {
                "overall_actions",
                "asset_actions",
                "communication_actions",
            },
        )
        self.assertEqual(result["communication_actions"], [])
        self.assertEqual(
            result["overall_actions"][0]["action_type"], "MONITOR"
        )

    def test_empty_notification_reason_is_rejected(self):
        for reason in (None, "", "   "):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(
                    ValueError, "notification_reason is required"
                ):
                    DecisionEngine().recommend(
                        self._risk_result(),
                        {
                            "requires_user_notification": True,
                            "notification_reason": reason,
                            "affected_user_group": None,
                        },
                    )

    def test_existing_risk_reasons_remain_unchanged(self):
        reasons = [
            "Critical Asset",
            "Production",
            "KEV",
            "CVSS 9.8",
            "Public Exploit",
        ]
        risk_result = self._risk_result("Critical", reasons)

        result = DecisionEngine().recommend(
            risk_result,
            {
                "requires_user_notification": True,
                "notification_reason": "User action is required",
            },
        )
        result["asset_actions"][0]["reasons"].append("Changed")
        result["communication_actions"][0]["reasons"].append(
            "Changed"
        )

        self.assertEqual(
            risk_result["asset_results"][0]["reasons"], reasons
        )
        self.assertIsNot(
            result["asset_actions"][0]["reasons"],
            risk_result["asset_results"][0]["reasons"],
        )

    def test_all_approved_levels_have_action_types(self):
        expected = {
            "Critical": (
                "REMEDIATE",
                "P1",
                "Patch Immediately",
                "Today",
            ),
            "High": (
                "REMEDIATE",
                "P2",
                "Patch This Week",
                "7 Days",
            ),
            "Medium": (
                "REMEDIATE",
                "P3",
                "Review and Schedule",
                "30 Days",
            ),
            "Low": (
                "MONITOR",
                "P4",
                "Monitor",
                "Next Review",
            ),
            "Informational": (
                "NO_ACTION",
                "P5",
                "No Action",
                "None",
            ),
        }

        for level, values in expected.items():
            with self.subTest(level=level):
                action = DecisionEngine().recommend(
                    self._risk_result(level)
                )["overall_actions"][0]
                self.assertEqual(
                    (
                        action["action_type"],
                        action["priority"],
                        action["recommendation"],
                        action["target"],
                    ),
                    values,
                )

    def test_policy_contains_only_allowed_action_types(self):
        self.assertEqual(
            {policy["action_type"] for policy in DECISION_POLICY.values()},
            {"REMEDIATE", "MONITOR", "NO_ACTION"},
        )

    def test_unknown_risk_level_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported risk level"):
            DecisionEngine().recommend(
                {
                    "overall_level": "Unknown",
                    "asset_results": [],
                }
            )


if __name__ == "__main__":
    unittest.main()
