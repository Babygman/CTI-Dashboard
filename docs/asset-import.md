# Asset CSV Import

## Purpose

The Asset CSV Import command bulk-loads the organization's Asset Inventory into the existing `Assets` table. Imported Assets are linked to existing Catalog Products so Impact Analysis, Risk Assessment, the Decision Engine, and the Security Operations Dashboard can identify affected infrastructure.

The importer supports CSV only. It does not create Product Catalog records, change the database schema, execute background work, or call external services.

## Command

Dry run first:

```powershell
flask import-assets --file assets/templates/asset-import-template.csv --dry-run
```

Actual import:

```powershell
flask import-assets --file C:\approved\company-assets.csv
```

The command must run with the normal Flask application configuration and SQL Server connection available.

## CSV format

Files must be valid UTF-8 CSV. A UTF-8 byte-order mark is accepted. The maximum file size is 10 MB.

### Required columns

| Column | Mapping and validation |
|---|---|
| AssetName | Required; maximum 200 characters; case-insensitive duplicate key |
| AssetType | Required; maximum 100 characters |
| Environment | Required free text; maximum 100 characters |
| Criticality | Required Boolean: `true`, `false`, `yes`, `no`, `1`, or `0` |
| CatalogVendor | Required; maximum 100 characters; matched to Catalog Product |
| CatalogProduct | Required; maximum 200 characters; matched to Catalog Product |

The current Asset model stores Environment as free text and Risk Assessment gives special meaning only to `Production`. The importer therefore validates presence and length without inventing a new environment enum.

### Optional columns

| Column | Mapping and validation |
|---|---|
| IPAddress | Trimmed and preserved in `Asset.Notes` |
| Hostname | Trimmed and preserved in `Asset.Notes` |
| OperatingSystem | Trimmed and preserved in `Asset.Notes` |
| Owner | `Asset.Owner`; maximum 200 characters |
| Location | `Asset.Location`; maximum 255 characters |
| Description | Preserved as the first part of `Asset.Notes` |
| Enabled | Optional Boolean; defaults to true |

`Enabled=true` maps to the existing Asset `Status` value `Active`. `Enabled=false` maps to `Disabled`, which Impact Analysis excludes because it selects only `Active` Assets.

After catalog matching, the canonical Catalog Product values are copied to the existing free-text `Asset.Vendor` and `Asset.Product` fields, and `Asset.CatalogProductId` is assigned.

## Product Catalog schema alignment

The importer uses the deployed `CatalogProducts` schema directly:

- `CatalogProductId` is stored on the Asset.
- `VendorName` and `ProductName` form the trimmed, case-insensitive exact match key.
- `Active` must equal 1 for a product to be eligible.

The catalog lookup query selects only `CatalogProductId`, `VendorName`, and `ProductName`, with an `Active = 1` predicate. It does not reference or assume `CatalogProducts.VendorId` or `CatalogProducts.Enabled`; neither column exists. The optional CSV field named `Enabled` controls the imported Asset's existing `Status` field only and is unrelated to Product Catalog activation.

## Product Catalog matching

`CatalogVendor` and `CatalogProduct` are trimmed and matched together against active rows in `CatalogProducts` using case-insensitive exact comparison.

The importer never creates a missing Product Catalog entry. A missing or ambiguous match produces a row-level error, skips that row, and allows remaining rows to continue.

The supplied [Asset import template](../assets/templates/asset-import-template.csv) uses `REPLACE_WITH_EXISTING_CATALOG_VENDOR` and `REPLACE_WITH_EXISTING_CATALOG_PRODUCT` placeholders because the repository does not guarantee production seed data. Replace both placeholders on every row with an exact existing active Catalog Product pair before importing.

## Duplicate behavior

Asset names are compared case-insensitively after trimming.

- If no existing Asset matches, one Asset is created.
- If exactly one Asset matches, that Asset is updated.
- If multiple existing Assets match case-insensitively, the row is skipped as ambiguous.
- Repeated Asset names within one CSV use the final valid row values and are reported as one create followed by updates, or as updates when the Asset already exists.

The importer does not add a database uniqueness constraint.

## Validation behavior

Blank rows are ignored and do not contribute to `Total rows`.

All text fields are trimmed. Required values must not be empty. Boolean values are case-insensitive and accept only:

```text
true, false, yes, no, 1, 0
```

Normal row errors include the CSV row number and a concise reason. Invalid rows are counted as both Skipped and Errors. A row error does not stop other rows.

CSV values are treated only as text. Formulas, commands, and code in fields are never evaluated or executed. Product and duplicate lookups use SQLAlchemy expressions rather than SQL assembled from CSV text.

## Dry-run procedure

1. Copy the template to an approved working location.
2. Replace Catalog Vendor/Product placeholders with existing active catalog values.
3. Populate the organization Asset rows.
4. Run:

   ```powershell
   flask import-assets --file C:\approved\company-assets.csv --dry-run
   ```

5. Review every row error and confirm the Created/Updated counts.
6. Query the Asset list if desired and confirm the dry run wrote nothing.

Dry run performs file parsing, header and row validation, catalog matching, duplicate detection, and summary calculation. It does not add or mutate Assets and explicitly rolls back its read transaction.

## Actual import procedure

1. Back up the database or confirm an approved restore point.
2. Complete a successful dry run against the exact file.
3. Confirm Product Catalog pairs and duplicate update counts.
4. Run:

   ```powershell
   flask import-assets --file C:\approved\company-assets.csv
   ```

5. Review Total rows, Valid rows, Created, Updated, Skipped, and Errors.
6. Verify imported records on `/assets` and confirm Impact Analysis sees active linked Assets.

## Transaction and rollback behavior

Catalog loading, duplicate detection, planned creates/updates, flush, and commit use one database transaction.

Expected row validation errors are skipped inside the import plan and do not cancel other valid rows. If an unexpected fatal exception occurs while applying the plan, the session is rolled back and none of that import's creates or updates remain. The CLI reports a generic rollback message and logs the exception without exposing a normal validation stack trace.

## Output example

```text
Row 4: Catalog Product not found for Example / Missing Product
Total rows : 5
Valid rows : 4
Created : 3
Updated : 1
Skipped : 1
Errors : 1
Dry run status : Yes
```

## Known limitations

- CSV only; Excel workbooks are unsupported.
- Imports are synchronous and limited to 10 MB.
- There is no database-level unique constraint on Asset Name, so pre-existing ambiguous duplicates must be resolved manually.
- Environment remains free text because the current model defines no environment enum.
- IP address, hostname, operating system, and description have no dedicated schema columns and are preserved in Notes.
- Enabled is represented through the existing Status field rather than a dedicated Boolean column.
- Catalog matching is case-insensitive exact matching only; aliases and fuzzy matching are not used.
- There is no import history, background processing, scheduler, API, approval, ticketing, notification, or Action Tracking.

