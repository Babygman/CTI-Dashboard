# Business Risk Assessment

## Architecture

The Business Risk Assessment Engine is a pure policy layer:

```text
Impact Analysis result
        |
        v
Risk policy weights
        |
        v
Per-Asset Business Risk
        |
        v
Overall Risk result
```

The engine accepts an existing impact result and explicit threat context. It does
not query a database, change Assets or Threats, create Actions, send
notifications, or persist risk results.

## Public API

`RiskAssessmentService.assess(impact_result, threat_context)` returns:

```python
{
    "overall_score": 100,
    "overall_level": "Critical",
    "asset_results": [
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
}
```

Threat context accepts:

- `cvss_score`: optional numeric value from 0.0 through 10.0;
- `kev`: boolean;
- `public_exploit`: boolean.

## Default scoring policy

| Condition | Points |
| --- | ---: |
| Affected Asset exists | 20 |
| Critical Asset | 20 |
| Production environment | 15 |
| KEV | 20 |
| CVSS 9.0–10.0 | 15 |
| CVSS 7.0–8.9 | 10 |
| Public Exploit | 10 |

The Asset-exists baseline contributes 20 points but is not repeated in the
conditional reasons list. Environment comparison is case-insensitive after
trimming surrounding whitespace.

The CVSS bands are mutually exclusive. A score of 9.0 or higher receives 15
points, while 7.0 through 8.9 receives 10 points.

The raw policy weights sum to 110 because both CVSS bands are listed, but those
bands are mutually exclusive. The maximum applicable score is therefore 100.
The Fortinet example with Critical Asset, Production, KEV, CVSS 9.8, and Public
Exploit returns 100. A score of 95 cannot be produced from the applicable stated
weights without changing one of them.

## Risk levels

| Score | Level |
| --- | --- |
| 90–100 | Critical |
| 70–89 | High |
| 40–69 | Medium |
| 20–39 | Low |
| 0–19 | Informational |

Overall score is the highest affected-Asset score. This prevents a single
Critical Asset from being diluted by averaging it with lower-risk Assets.

An unmatched impact result or a result without affected Assets returns score
`0`, level `Informational`, and an empty Asset result list.

## Configurable policy

The constructor accepts partial weight overrides:

```python
service = RiskAssessmentService(
    {
        "asset_exists": 10,
        "critical_asset": 25,
        "production": 20,
    }
)
```

Supported keys are:

- `asset_exists`
- `critical_asset`
- `production`
- `kev`
- `cvss_critical`
- `cvss_high`
- `public_exploit`

Values must be non-negative numbers. Unknown keys are rejected.

## CLI usage

The CLI builds threat context only from its supplied options; there is no
collector integration.

Windows PowerShell:

```powershell
flask assess-risk --vendor Fortinet --product FortiOS --cvss 9.8 --kev --public-exploit
```

Bash:

```bash
flask assess-risk \
    --vendor Fortinet \
    --product FortiOS \
    --cvss 9.8 \
    --kev \
    --public-exploit
```

With one Critical Production Asset, the default policy output includes:

```text
Overall Risk
Critical
Score
100
Affected Assets

FG200E
Risk
Critical
Score
100
Reasons
Critical Asset
Production
KEV
CVSS 9.8
Public Exploit
```

Product and CVSS are required CLI options. CVSS is validated from 0.0 through
10.0. KEV and Public Exploit are optional flags.

## Verification

Focused tests run without SQL or a database:

```powershell
python -B -m unittest tests.test_risk_assessment tests.test_assess_risk_cli -v
```

CLI tests mock Impact Analysis and verify output, inputs, flags, validation, and
risk calculation without opening a database connection.

## Current limitations

- Policy values are process-local constructor configuration.
- Risk levels are fixed in code.
- Overall risk uses maximum score rather than average or aggregate exposure.
- CVSS temporal and environmental metrics are not considered.
- Asset owner, location, compensating controls, and business service dependency
  do not affect scoring.
- Threat age, severity labels, exploit maturity, and remediation state are not
  included.
- Risk results are not persisted, versioned, or audited.
- No Actions, tickets, approvals, or notifications are created.

## Future external policy file

A future sprint may load versioned policy weights and level thresholds from an
external configuration file. That design should include schema validation,
policy identifiers, effective dates, safe defaults, change audit history, and
tests that reproduce historical assessments. External policy loading is not
implemented in Sprint 8B.
