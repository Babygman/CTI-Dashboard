# Decision Engine

## Purpose

The Decision Engine converts Business Risk into two operational outcomes:

1. Vulnerability remediation or monitoring for IT teams.
2. User security awareness communication when explicit threat context requires it.

It is a read-only policy layer. It does not store actions, create tickets, send email or Teams messages, or write to the database.

## Architecture

```text
Impact Analysis
      |
Risk Assessment ---- Threat Communication Context
      |                         |
      +------ Decision Engine --+
                     |
          +----------+-----------+
          |                      |
   Remediation Actions   Communication Actions
```

The Decision Engine does not infer user notification from CVSS, KEV status, severity, or risk level. A caller must explicitly set `requires_user_notification`.

## Public API

```python
result = DecisionEngine().recommend(
    risk_result,
    {
        "requires_user_notification": True,
        "notification_reason": (
            "Phishing campaign targeting Outlook users"
        ),
        "affected_user_group": "All Employees",
    },
)
```

`threat_context` is optional. When it is omitted, the existing remediation policy is applied and `communication_actions` is empty.

## Return structure

```python
{
    "overall_actions": [
        {
            "action_type": "REMEDIATE",
            "priority": "P2",
            "recommendation": "Patch This Week",
            "target": "7 Days",
        }
    ],
    "asset_actions": [
        {
            "asset_name": "OUTLOOK-01",
            "action_type": "REMEDIATE",
            "priority": "P2",
            "recommendation": "Patch This Week",
            "target": "7 Days",
            "reasons": ["Production", "CVSS 8.8"],
        }
    ],
    "communication_actions": [
        {
            "action_type": "NOTIFY_USERS",
            "priority": "P3",
            "recommendation": "Notify Users",
            "target": "As Soon As Practical",
            "affected_user_group": "All Employees",
            "reasons": [
                "Phishing campaign targeting Outlook users"
            ],
        }
    ],
}
```

Allowed `action_type` values are:

- `REMEDIATE`
- `NOTIFY_USERS`
- `MONITOR`
- `NO_ACTION`

Communication recommendations are additional. They never replace the overall or per-Asset remediation outcome.

## Remediation policy

| Risk level | Action type | Priority | Recommendation | Target |
|---|---|---|---|---|
| Critical | REMEDIATE | P1 | Patch Immediately | Today |
| High | REMEDIATE | P2 | Patch This Week | 7 Days |
| Medium | REMEDIATE | P3 | Review and Schedule | 30 Days |
| Low | MONITOR | P4 | Monitor | Next Review |
| Informational | NO_ACTION | P5 | No Action | None |

The overall recommendation is selected from `overall_level`. Each Asset recommendation is selected independently from that Asset's risk level. Unknown risk levels are rejected instead of silently selecting a fallback policy.

## Communication policy

When `requires_user_notification` is true, the engine adds this recommendation:

| Action type | Priority | Recommendation | Target |
|---|---|---|---|
| NOTIFY_USERS | P3 | Notify Users | As Soon As Practical |

`notification_reason` must contain non-whitespace text. `affected_user_group` is optional and may be null. Notification context is never derived from CVSS alone.

## Reason generation

Asset action reasons are copied verbatim from Risk Assessment, preserving content and order. Examples include:

- Critical Asset
- Production
- KEV
- CVSS 9.8
- Public Exploit

The communication action contains the explicit `notification_reason` as its reason. Copying risk reasons ensures consumers cannot mutate the upstream Risk Assessment result.

## CLI usage

Remediation only:

```powershell
flask recommend-action --vendor Fortinet --product FortiOS --cvss 9.8 --kev --public-exploit
```

Remediation and user notification:

```powershell
flask recommend-action --vendor Microsoft --product Outlook --cvss 8.8 --notify-users --notification-reason "Phishing campaign targeting Outlook users" --affected-user-group "All Employees"
```

Options:

- `--product` and `--cvss` are required.
- CVSS must be between 0.0 and 10.0.
- `--notify-users` explicitly requests a communication recommendation.
- `--notification-reason` is required and must not be empty when `--notify-users` is set.
- `--affected-user-group` is optional.

The CLI prints remediation and communication as separate recommendations. It does not send any communication.

## Verification

Focused tests:

```powershell
python -B -m unittest tests.test_decision_engine tests.test_recommend_action_cli -v
```

Combined Risk and Decision tests:

```powershell
python -B -m unittest tests.test_risk_assessment tests.test_assess_risk_cli tests.test_decision_engine tests.test_recommend_action_cli -v
```

CLI tests replace Impact Analysis at the command boundary, so they execute no SQL and make no database calls.

## Current limitations

- Policies are static application code and cannot be configured per organization.
- Notification priority is fixed at P3.
- Targets are labels, not calculated deadlines.
- The engine does not generate email, Teams messages, or awareness content.
- Communication audience and reason depend entirely on explicit caller input.
- Recommendations have no owner, workflow state, approval, audit history, or persistence.
- Callers of the earlier singular `overall_action` result must consume the new `overall_actions` list; omitting `threat_context` remains supported.

## Future Action Tracking

A future Action Tracking component can consume these independent recommendation lists to create remediation work and communication tasks. It should remain separate from the Decision Engine and add ownership, due dates, status transitions, approvals, deduplication, audit history, ticket references, content generation, delivery integrations, and notification rules. None of those capabilities are included here.
