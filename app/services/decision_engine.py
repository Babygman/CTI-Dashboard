DECISION_POLICY = {
    "Critical": {
        "action_type": "REMEDIATE",
        "priority": "P1",
        "recommendation": "Patch Immediately",
        "target": "Today",
    },
    "High": {
        "action_type": "REMEDIATE",
        "priority": "P2",
        "recommendation": "Patch This Week",
        "target": "7 Days",
    },
    "Medium": {
        "action_type": "REMEDIATE",
        "priority": "P3",
        "recommendation": "Review and Schedule",
        "target": "30 Days",
    },
    "Low": {
        "action_type": "MONITOR",
        "priority": "P4",
        "recommendation": "Monitor",
        "target": "Next Review",
    },
    "Informational": {
        "action_type": "NO_ACTION",
        "priority": "P5",
        "recommendation": "No Action",
        "target": "None",
    },
}


class DecisionEngine:
    """Convert a Business Risk result into recommendations."""

    def recommend(self, risk_result, threat_context=None):
        overall_level = risk_result.get(
            "overall_level", "Informational"
        )
        overall_policy = self._policy_for(overall_level)
        overall_actions = [self._recommendation(overall_policy)]

        asset_actions = []
        for asset_result in risk_result.get("asset_results") or []:
            policy = self._policy_for(asset_result.get("level"))
            asset_actions.append(
                {
                    "asset_name": asset_result.get("asset_name"),
                    "action_type": policy["action_type"],
                    "priority": policy["priority"],
                    "recommendation": policy["recommendation"],
                    "target": policy["target"],
                    "reasons": list(asset_result.get("reasons") or []),
                }
            )

        return {
            "overall_actions": overall_actions,
            "asset_actions": asset_actions,
            "communication_actions": self._communication_actions(
                threat_context
            ),
        }

    @staticmethod
    def _recommendation(policy):
        return {
            "action_type": policy["action_type"],
            "priority": policy["priority"],
            "recommendation": policy["recommendation"],
            "target": policy["target"],
        }

    @staticmethod
    def _communication_actions(threat_context):
        context = threat_context or {}
        if not context.get("requires_user_notification", False):
            return []

        notification_reason = context.get("notification_reason")
        if not isinstance(notification_reason, str) or not (
            notification_reason := notification_reason.strip()
        ):
            raise ValueError(
                "notification_reason is required when user "
                "notification is requested"
            )

        return [
            {
                "action_type": "NOTIFY_USERS",
                "priority": "P3",
                "recommendation": "Notify Users",
                "target": "As Soon As Practical",
                "affected_user_group": context.get(
                    "affected_user_group"
                ),
                "reasons": [notification_reason],
            }
        ]

    @staticmethod
    def _policy_for(level):
        try:
            return DECISION_POLICY[level]
        except KeyError:
            raise ValueError(
                f"Unsupported risk level: {level!r}"
            ) from None
