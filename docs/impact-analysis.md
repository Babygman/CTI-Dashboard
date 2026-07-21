# Impact Analysis Engine

## Architecture

The Impact Analysis Engine is a read-only layer that connects product
normalization to company Asset inventory:

```text
Threat vendor/product name
        |
        v
ProductNormalizer
        |
        v
CatalogProduct
        |
        v
Active Assets linked by CatalogProductId
        |
        v
Impact result
```

This sprint does not create actions, tickets, notifications, or persisted impact
records. It does not perform a database or schema change.

## Public API

`ImpactAnalysisService.analyze(vendor_name, product_name)` returns:

```python
{
    "matched": True,
    "catalog_product_id": 1,
    "product_name": "FortiGate",
    "affected_asset_count": 2,
    "affected_assets": [
        {
            "asset_name": "FG200E",
            "owner": "IT",
            "environment": "Production",
            "critical": True,
            "status": "Active",
            "location": "Bangkok",
        }
    ],
}
```

An unmatched product returns `matched=False`,
`catalog_product_id=None`, count `0`, and an empty Asset list.

## Workflow

1. Call `ProductNormalizer.normalize(vendor_name, product_name)` once.
2. If normalization does not match, return immediately without querying Assets.
3. If normalization matches, select Assets whose nullable
   `CatalogProductId` equals the normalized catalog product identifier.
4. Include only Assets whose existing Status value equals `Active`
   case-insensitively.
5. Sort by:
   - Critical descending;
   - AssetName ascending; and
   - AssetId ascending as a deterministic tie-breaker.
6. Return only Asset Name, Owner, Environment, Critical, Status, and Location.

The service issues no INSERT, UPDATE, DELETE, commit, or rollback operation.

## CLI usage

Windows PowerShell:

```powershell
flask analyze-impact --vendor Fortinet --product FortiOS
```

Bash:

```bash
flask analyze-impact \
    --vendor Fortinet \
    --product FortiOS
```

Expected output:

```text
Matched : Yes
Catalog Product : FortiGate
Affected Assets : 2

----------------------
FG200E
Owner : IT
Environment : Production
Critical : Yes

----------------------
FG200E-DR
Owner : IT
Environment : DR
Critical : Yes
```

Vendor is optional for alias-only normalization. Product is required.

## Manual test steps

1. Confirm the Sprint 7B catalog and nullable Asset relationship have already
   been applied manually. Sprint 8A has no SQL to execute.
2. Create active catalog product `Fortinet — FortiGate`.
3. Add active alias `FortiOS`.
4. Link two Assets to FortiGate and set their Status to `Active`.
5. Mark one or both Assets Critical.
6. Link another Asset but set its Status to `Retired`.
7. Run:

   ```powershell
   flask analyze-impact --vendor Fortinet --product FortiOS
   ```

8. Confirm only Active Assets appear, Critical Assets appear first, and names
   are ordered alphabetically within the same Critical value.
9. Run an unknown product and confirm zero affected Assets.
10. Confirm Asset, CatalogProduct, ProductAlias, Threat, and collector data are
    unchanged.

Automated tests use an isolated in-memory database:

```powershell
python -B -m unittest tests.test_impact_analysis tests.test_analyze_impact_cli -v
```

## Current limitations

- Asset activity is inferred from the free-text Status value `Active`; there is
  no separate Asset Active boolean.
- Version compatibility is not evaluated.
- Product normalization ambiguity remains governed by ProductNormalizer.
- Assets without CatalogProductId are not included.
- The result is generated on demand and is not persisted or audited.
- No Threat identifier, CVE, severity, exploitability, or exposure context is
  included.
- No pagination is applied to affected Assets.

## Future Action Engine

A later Action Engine may consume an explicit, reviewed impact result to create
tasks, tickets, notifications, remediation ownership, due dates, or audit
records. That future engine should remain separate from read-only analysis and
must define authorization, deduplication, transaction boundaries, retry
behavior, escalation rules, and operator approval. Sprint 8A performs none of
those actions.
