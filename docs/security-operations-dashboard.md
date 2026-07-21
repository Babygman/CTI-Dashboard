# Security Operations Dashboard

## Business objective

The Security Operations Dashboard turns consolidated threat intelligence into a bounded, read-only operational view for IT teams. It answers:

- What must be patched today?
- What must be patched this week?
- What should be reviewed or monitored?
- What should be communicated to users?
- Is threat collection operating normally?

Operational work is shown before collection statistics so urgent remediation is visible first.

## Architecture

```text
Recent Threats (bounded and ordered)
              |
       Impact Analysis
              |
       Risk Assessment
              |
       Decision Engine
              |
 OperationsDashboardService
              |
 Security Operations Dashboard
```

`OperationsDashboardService` orchestrates the existing `ImpactAnalysisService`, `RiskAssessmentService`, and `DecisionEngine`. The dashboard route contains no normalization, scoring, or decision policy.

## Dashboard sections

The layout is ordered as follows:

1. Security Operations title
2. Operations summary cards
3. Patch Immediately
4. Patch This Week
5. Review and Schedule
6. User Awareness
7. Monitoring
8. Collection Health
9. Existing severity and Top 10 Vendor charts

The operations summary reports:

- Patch Immediately
- Patch This Week
- Review and Schedule
- Notify Users
- Monitor
- Analysis Errors

Asset work items contain the Threat identifier, Asset, Vendor, Product, risk level, priority, recommendation, target, and reasons. Communication items contain the Threat identifier, recommendation, priority, target, affected user group, and explicit notification reason.

`NO_ACTION` decisions do not appear in operational work lists.

## Data flow

1. Select the most recent Threats from SQL Server.
2. Eager-load each Threat's Vendor in the bounded query.
3. For each selected Threat, call Impact Analysis with the available Vendor and product input.
4. Build Risk Assessment context from existing Threat fields only.
5. Pass the Risk result to the Decision Engine.
6. Group Asset recommendations by action type and priority.
7. Add explicit `NOTIFY_USERS` recommendations to User Awareness.
8. Return a presentation-ready view model to Jinja.

Jinja performs display only and does not call service logic. Normal autoescaping remains enabled, and Threat text is not rendered with `safe`.

## Threat analysis limit

`OPERATIONS_DASHBOARD_THREAT_LIMIT` controls the maximum Threats analyzed per request. The default is 100 and can be set through the environment:

```text
OPERATIONS_DASHBOARD_THREAT_LIMIT=100
```

Invalid, zero, or negative configured values fall back to 100. Selection uses deterministic ordering:

```text
Threat.CreatedAt DESC
Threat.ThreatId DESC
```

The database query applies the limit before Threats are loaded. An accepted in-memory Threat iterable is also truncated before analysis.

## Error isolation

Every Threat is analyzed inside its own exception boundary. If one Threat fails:

- the page continues processing remaining Threats;
- the Analysis Errors count increases;
- a generic error item is returned to the view model;
- the exception is logged with `ThreatId`;
- exception details and stack traces are not exposed in the UI.

## User notification limitation

The current `Threat` model has no persisted user-notification classification, notification reason, or affected user group. The dashboard therefore does not infer user communication from CVSS, severity, KEV, or risk level. With current production data, `communication_actions` remains empty.

The service can display a `NOTIFY_USERS` result when the existing Decision Engine receives explicit communication context from a future persisted classification. No temporary rule or hardcoded notification condition has been added.

## Product identification limitation

The current `Threat` model does not contain a dedicated Product column. The service uses an accepted Threat object's Product/ProductName value when available and otherwise passes the existing Threat title as the product input. Product normalization can only find affected Assets when that value matches a Catalog Product or Product Alias. No collector parsing or source-specific metadata interpretation was duplicated in the dashboard.

## Collection health

The previous read-only collection metrics remain available below operational work:

- Total Threats
- Critical Threats
- High Threats
- KEV Threats
- Last Update
- Total Source Items
- CISA Items
- NVD Items
- Multi-source Threats
- Enabled Sources
- Latest Collection Run details
- Severity distribution
- Top 10 Vendors

## Read-only and performance safeguards

- No database schema or SQL script changes.
- No inserts, updates, deletes, flushes, or commits.
- No external API calls.
- No collector changes.
- No mutation of Threat, Asset, risk, or recommendation objects.
- Recent Threats are limited in SQL.
- Vendor is eager-loaded to avoid a Vendor N+1 query.
- Existing dashboard metrics continue to use aggregate SQL queries.
- Per-Threat errors are isolated and logged.

Impact Analysis still performs catalog and Asset lookups for each selected Threat. The limit is the primary guard on that work in this MVP.

## Verification

Focused service and dashboard tests:

```powershell
python -B -m unittest tests.test_operations_dashboard tests.test_security_operations_dashboard -v
```

Combined Risk, Decision, and Operations tests:

```powershell
python -B -m unittest tests.test_risk_assessment tests.test_assess_risk_cli tests.test_decision_engine tests.test_recommend_action_cli tests.test_operations_dashboard tests.test_security_operations_dashboard -v
```

The focused tests cover grouping, all operational queues, communication results, `NO_ACTION` exclusion, failure isolation, error counting, limit enforcement, SQL Server ordering, route rendering, empty states, collection metrics, and absence of dashboard database writes.

## Future Action Tracking

A future Action Tracking component may persist selected remediation and communication recommendations with owners, due dates, approvals, workflow state, audit history, ticket references, and delivery status. It should consume the dashboard service's outputs rather than move persistence into this read-only service. Authentication, authorization, notification delivery, and deduplication must be designed before that component is introduced.
