# Asset Inventory Foundation

## Scope

Sprint 7A adds storage and manual CRUD management for company assets. Assets are
standalone inventory records. This module does not match assets to threats, call
collectors, scan infrastructure, expose an API, or change the dashboard.

## Data model

The SQLAlchemy `Asset` model maps to `dbo.Assets`.

| Column | SQL Server type | Rules/default |
| --- | --- | --- |
| AssetId | INT IDENTITY | Primary key |
| AssetName | NVARCHAR(200) | Required |
| Vendor | NVARCHAR(100) | Optional |
| Product | NVARCHAR(200) | Optional |
| Version | NVARCHAR(100) | Optional |
| AssetType | NVARCHAR(100) | Optional |
| Critical | BIT | Required, default 0 |
| Environment | NVARCHAR(100) | Optional |
| Owner | NVARCHAR(200) | Optional |
| Location | NVARCHAR(255) | Optional |
| Status | NVARCHAR(50) | Required, default `Active` |
| Notes | NVARCHAR(MAX) | Optional |
| CreatedAt | DATETIME2 | Required, UTC database default |
| UpdatedAt | DATETIME2 | Required, UTC database default; updated by SQLAlchemy |

No foreign keys or relationships are introduced in this sprint. In particular,
the free-text Vendor and Product fields are not linked to `dbo.Vendors` and
are not used for threat matching.

## Application behavior

The Assets menu opens `/assets`. The blueprint provides:

- `GET /assets`: list, search, sort, reset, and paginate assets;
- `GET|POST /assets/add`: create an asset;
- `GET|POST /assets/<asset_id>/edit`: update an asset; and
- `POST /assets/<asset_id>/delete`: delete an asset.

Asset Name is required. Server-side validation enforces the SQL column lengths.
Delete uses POST and requires browser confirmation. Successful changes use the
project's existing Bootstrap flash-message pattern.

Search covers Asset Name, Vendor, Product, Owner, and Location. Lists contain 10
records per page and preserve search/sort state.

## Manual SQL execution

The application does not create the production table automatically. Apply the
idempotent Assets block from `database/init.sql` manually:

1. Back up the database or confirm an approved restore point.
2. Open SQL Server Management Studio and connect to the CTIDashboard instance.
3. Select the `CTIDashboard` database.
4. Execute only the block beginning with:

   ```sql
   IF OBJECT_ID(N'dbo.Assets', N'U') IS NULL
   BEGIN
       CREATE TABLE dbo.Assets
   ```

   and ending at its following `GO`.
5. Verify the table and columns:

   ```sql
   SELECT
       c.ORDINAL_POSITION,
       c.COLUMN_NAME,
       c.DATA_TYPE,
       c.CHARACTER_MAXIMUM_LENGTH,
       c.IS_NULLABLE,
       c.COLUMN_DEFAULT
   FROM INFORMATION_SCHEMA.COLUMNS AS c
   WHERE c.TABLE_SCHEMA = N'dbo'
     AND c.TABLE_NAME = N'Assets'
   ORDER BY c.ORDINAL_POSITION;
   ```

6. Restart Flask, then open `/assets`.

The block is idempotent: if `dbo.Assets` already exists, it does not recreate
or alter the table. Existing databases therefore require this manual execution
before the Assets routes can query data.

## Manual test procedure

1. Confirm `GET /assets` returns HTTP 200 and shows the Assets menu entry.
2. Select **+ Add Asset**.
3. Submit an empty Asset Name and confirm the required validation message.
4. Create an asset with Vendor, Product, Version, Type, Critical, Environment,
   Owner, Location, Status, and Notes values.
5. Confirm the success message and the new row on the list.
6. Search using part of the asset name, vendor, product, owner, or location.
7. Sort the list in both directions and navigate pagination when more than 10
   records exist.
8. Edit the asset, including toggling Critical, and confirm persisted changes.
9. Cancel an add or edit and confirm the list opens without saving.
10. Delete the test asset, accept browser confirmation, and confirm the success
    message.
11. Request a missing edit identifier and confirm HTTP 404.
12. Confirm a GET request to the delete URL returns HTTP 405.

## Verification performed during development

- Python syntax parsing passed for all application Python files.
- All Jinja templates compiled successfully.
- Blueprint registration exposed the four expected Asset routes.
- Add, validation, list, search, sort, edit, POST-only delete, 404, flash, and
  persisted-value checks passed against an isolated in-memory test database.
- The configured SQL Server database was not modified during verification.

## Current limitations

- Asset matching and vulnerability exposure calculations are intentionally not
  implemented.
- Vendor and Product are free text and can contain spelling or naming variants.
- No import, export, discovery, scanning, API, authentication, or dashboard
  integration is included.
- The module follows the application's existing form security posture; CSRF
  protection is not introduced by this sprint.
