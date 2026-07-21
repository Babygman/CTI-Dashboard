# Product Catalog and Alias Foundation

## Purpose

Sprint 7B introduces a normalized company product catalog that can be linked to
Asset records. It creates a stable product identity and a controlled set of
aliases for future matching work without implementing threat-to-asset, CVE, CPE,
collector, dashboard, notification, or discovery behavior.

Catalog vendor names are stored directly in `dbo.CatalogProducts.VendorName`.
The catalog does not modify, reference, or reuse the existing CTI/feed
`dbo.Vendors` table.

## Data model

### CatalogProducts

`dbo.CatalogProducts` stores one normalized product identity per vendor and
product-name pair.

- VendorName and ProductName are required and unique together.
- ProductFamily, TechnologyCategory, and Description are optional.
- Active defaults to true.
- VendorName, ProductName, and Active are indexed.
- CreatedAt and UpdatedAt use UTC database defaults; SQLAlchemy updates
  UpdatedAt when the application edits a product.

### ProductAliases

`dbo.ProductAliases` stores alternate names for one catalog product.

- CatalogProductId and Alias are required.
- Alias is unique within its catalog product.
- Alias is indexed.
- AliasType is optional and the UI offers ProductName, Family, Model,
  OperatingSystem, CPEKeyword, CommonName, and Other.
- Deleting a CatalogProduct cascades only to its ProductAliases.

### Assets relationship

`dbo.Assets.CatalogProductId` is nullable and references
`dbo.CatalogProducts.CatalogProductId` without delete cascade.

Existing Asset Vendor, Product, and Version columns remain unchanged and
editable. Existing asset records remain valid because the new foreign key is
nullable. The application performs no migration, inference, or automatic
matching. Product deletion is blocked while an Asset links to it.

The Asset form displays catalog choices as:

```text
VendorName โ€” ProductName
```

## Application routes

- `GET /product-catalog`: searchable, sortable, paginated product list.
- `GET|POST /product-catalog/add`: add a catalog product.
- `GET /product-catalog/<id>`: product detail and alias list.
- `GET|POST /product-catalog/<id>/edit`: edit a catalog product.
- `POST /product-catalog/<id>/delete`: delete an unreferenced product.
- `GET|POST /product-catalog/<id>/aliases/add`: add an alias.
- `POST /product-catalog/<id>/aliases/<alias_id>/delete`: delete an alias.

Product and alias duplicate checks are case-insensitive in the application.
Database unique constraints provide transaction-race protection. Missing
products and aliases return HTTP 404, and all deletion routes are POST-only.

## Manual SQL execution

Do not use `db.create_all()` against production. Back up the database or
confirm a restore point, connect to the `CTIDashboard` database in SQL Server
Management Studio, and execute the following blocks in this exact order.

The first block is the Sprint 7A prerequisite and is safe to rerun. The remaining
blocks create the catalog, aliases, nullable Asset link, foreign key, and indexes.
All blocks are idempotent.

```sql
USE CTIDashboard;
GO
IF OBJECT_ID(N'dbo.Assets', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Assets
    (
        AssetId INT IDENTITY(1,1) PRIMARY KEY,
        AssetName NVARCHAR(200) NOT NULL,
        Vendor NVARCHAR(100) NULL,
        Product NVARCHAR(200) NULL,
        Version NVARCHAR(100) NULL,
        AssetType NVARCHAR(100) NULL,
        Critical BIT NOT NULL
            CONSTRAINT DF_Assets_Critical DEFAULT (0),
        Environment NVARCHAR(100) NULL,
        Owner NVARCHAR(200) NULL,
        Location NVARCHAR(255) NULL,
        Status NVARCHAR(50) NOT NULL
            CONSTRAINT DF_Assets_Status DEFAULT (N'Active'),
        Notes NVARCHAR(MAX) NULL,
        CreatedAt DATETIME2 NOT NULL
            CONSTRAINT DF_Assets_CreatedAt DEFAULT (SYSUTCDATETIME()),
        UpdatedAt DATETIME2 NOT NULL
            CONSTRAINT DF_Assets_UpdatedAt DEFAULT (SYSUTCDATETIME())
    );
END;
GO

IF OBJECT_ID(N'dbo.CatalogProducts', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.CatalogProducts
    (
        CatalogProductId INT IDENTITY(1,1) PRIMARY KEY,
        VendorName NVARCHAR(100) NOT NULL,
        ProductName NVARCHAR(200) NOT NULL,
        ProductFamily NVARCHAR(100) NULL,
        TechnologyCategory NVARCHAR(100) NULL,
        Description NVARCHAR(MAX) NULL,
        Active BIT NOT NULL
            CONSTRAINT DF_CatalogProducts_Active DEFAULT (1),
        CreatedAt DATETIME2 NOT NULL
            CONSTRAINT DF_CatalogProducts_CreatedAt
                DEFAULT (SYSUTCDATETIME()),
        UpdatedAt DATETIME2 NOT NULL
            CONSTRAINT DF_CatalogProducts_UpdatedAt
                DEFAULT (SYSUTCDATETIME()),

        CONSTRAINT UQ_CatalogProducts_VendorName_ProductName
            UNIQUE (VendorName, ProductName)
    );
END;
GO

IF NOT EXISTS
(
    SELECT 1
    FROM sys.indexes
    WHERE object_id = OBJECT_ID(N'dbo.CatalogProducts')
      AND name = N'IX_CatalogProducts_VendorName'
)
BEGIN
    CREATE INDEX IX_CatalogProducts_VendorName
        ON dbo.CatalogProducts(VendorName);
END;
GO

IF NOT EXISTS
(
    SELECT 1
    FROM sys.indexes
    WHERE object_id = OBJECT_ID(N'dbo.CatalogProducts')
      AND name = N'IX_CatalogProducts_ProductName'
)
BEGIN
    CREATE INDEX IX_CatalogProducts_ProductName
        ON dbo.CatalogProducts(ProductName);
END;
GO

IF NOT EXISTS
(
    SELECT 1
    FROM sys.indexes
    WHERE object_id = OBJECT_ID(N'dbo.CatalogProducts')
      AND name = N'IX_CatalogProducts_Active'
)
BEGIN
    CREATE INDEX IX_CatalogProducts_Active
        ON dbo.CatalogProducts(Active);
END;
GO

IF OBJECT_ID(N'dbo.ProductAliases', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.ProductAliases
    (
        ProductAliasId INT IDENTITY(1,1) PRIMARY KEY,
        CatalogProductId INT NOT NULL,
        Alias NVARCHAR(200) NOT NULL,
        AliasType NVARCHAR(50) NULL,
        Active BIT NOT NULL
            CONSTRAINT DF_ProductAliases_Active DEFAULT (1),
        CreatedAt DATETIME2 NOT NULL
            CONSTRAINT DF_ProductAliases_CreatedAt
                DEFAULT (SYSUTCDATETIME()),

        CONSTRAINT FK_ProductAliases_CatalogProducts
            FOREIGN KEY (CatalogProductId)
            REFERENCES dbo.CatalogProducts(CatalogProductId)
            ON DELETE CASCADE,
        CONSTRAINT UQ_ProductAliases_CatalogProductId_Alias
            UNIQUE (CatalogProductId, Alias)
    );
END;
GO

IF NOT EXISTS
(
    SELECT 1
    FROM sys.indexes
    WHERE object_id = OBJECT_ID(N'dbo.ProductAliases')
      AND name = N'IX_ProductAliases_Alias'
)
BEGIN
    CREATE INDEX IX_ProductAliases_Alias
        ON dbo.ProductAliases(Alias);
END;
GO

IF OBJECT_ID(N'dbo.Assets', N'U') IS NOT NULL
   AND COL_LENGTH(N'dbo.Assets', N'CatalogProductId') IS NULL
BEGIN
    ALTER TABLE dbo.Assets
        ADD CatalogProductId INT NULL;
END;
GO

IF OBJECT_ID(N'dbo.FK_Assets_CatalogProducts', N'F') IS NULL
   AND OBJECT_ID(N'dbo.Assets', N'U') IS NOT NULL
   AND OBJECT_ID(N'dbo.CatalogProducts', N'U') IS NOT NULL
BEGIN
    ALTER TABLE dbo.Assets WITH CHECK
        ADD CONSTRAINT FK_Assets_CatalogProducts
            FOREIGN KEY (CatalogProductId)
            REFERENCES dbo.CatalogProducts(CatalogProductId);
END;
GO

IF NOT EXISTS
(
    SELECT 1
    FROM sys.indexes
    WHERE object_id = OBJECT_ID(N'dbo.Assets')
      AND name = N'IX_Assets_CatalogProductId'
)
BEGIN
    CREATE INDEX IX_Assets_CatalogProductId
        ON dbo.Assets(CatalogProductId);
END;
GO
```

After execution, verify the objects:

```sql
SELECT OBJECT_ID(N'dbo.CatalogProducts', N'U') AS CatalogProductsObjectId;
SELECT OBJECT_ID(N'dbo.ProductAliases', N'U') AS ProductAliasesObjectId;
SELECT COL_LENGTH(N'dbo.Assets', N'CatalogProductId')
    AS AssetsCatalogProductIdLength;
SELECT OBJECT_ID(N'dbo.FK_Assets_CatalogProducts', N'F')
    AS AssetsCatalogProductForeignKeyId;
SELECT OBJECT_ID(N'dbo.FK_ProductAliases_CatalogProducts', N'F')
    AS ProductAliasesCatalogProductForeignKeyId;
```

Restart Flask after applying the DDL.

## Manual test procedure

1. Confirm the Product Catalog menu entry opens `/product-catalog`.
2. Submit an empty product form and confirm Vendor and Product errors.
3. Add a product and verify all list columns and the detail page.
4. Attempt the same vendor/product with different letter casing and confirm the
   duplicate validation message.
5. Edit the product and confirm the saved values and Active state.
6. Add an alias, then attempt the same alias with different casing and confirm
   duplicate validation.
7. Confirm Alias Count updates on the product list.
8. Confirm product and alias delete URLs reject GET with HTTP 405.
9. Link an Asset through the Catalog Product dropdown and confirm the Asset list
   displays `VendorName โ€” ProductName`.
10. Confirm the original Asset Vendor, Product, and Version values remain
    editable and unchanged unless manually edited.
11. Attempt to delete a linked product and confirm deletion is blocked.
12. Unlink the Asset, delete the product, and confirm its aliases cascade.
13. Request missing product and alias identifiers and confirm HTTP 404.
14. Confirm the existing Dashboard, Vendors, Threats, and Assets pages return
    HTTP 200 after the production DDL is applied.

## Curated enterprise seed

`database/seed_catalog_products.sql` provides an optional, manually executed Version 1.0 seed containing 38 focused enterprise products and 54 common-name aliases. It is not run by the Application Factory, tests, or `database/init.sql`.

The script:

- requires the existing `CatalogProducts` and `ProductAliases` tables;
- matches products by trimmed, case-insensitive `VendorName + ProductName`;
- preserves existing `CatalogProductId` values, including an existing Fortinet / FortiGate row;
- updates canonical naming and product metadata;
- reactivates inactive matching products and aliases;
- inserts only missing products and aliases;
- rejects ambiguous existing case-insensitive product or alias mappings;
- uses `SET XACT_ABORT ON`, one transaction, TRY/CATCH, and rollback;
- returns separate product and alias outcome summaries.

The seed follows the existing catalog design: FortiGate is canonical, while `Fortigate` and `FortiOS` are aliases of FortiGate. This is intentional because the normalizer evaluates aliases before canonical names and the existing regression suite already treats FortiOS as a FortiGate alias.

Manual execution:

1. Back up the CTIDashboard database or confirm an approved restore point.
2. Review the desired product and alias rows for the target environment.
3. Open SQL Server Management Studio and select the CTIDashboard database.
4. Execute `database/seed_catalog_products.sql` as one batch.
5. Review both returned summaries.
6. Run the script a second time in a controlled environment and confirm products and aliases are reported as unchanged.
7. Verify common aliases with `flask normalize-product` before importing Assets.

## Documentation-only seed examples

These examples are not inserted automatically.

### Fortinet

| Vendor | Product | Family | Technology Category |
| --- | --- | --- | --- |
| Fortinet | FortiGate | FortiGate | Firewall |

Aliases:

- FortiGate
- FortiOS
- FG200E
- FG-200E

### Microsoft

| Vendor | Product | Family | Technology Category |
| --- | --- | --- | --- |
| Microsoft | Windows Server | Windows Server | Server Operating System |

Aliases:

- Windows Server
- Windows Server 2019
- Windows Server 2022

## Future use in Asset Matching

A later sprint can compare normalized collector or threat product names with
CatalogProduct names and ProductAliases, then evaluate linked Assets. That later
work must define matching confidence, version semantics, CPE parsing, conflict
resolution, and auditability. None of those behaviors are implemented here.

## Known limitations

- Vendor and product normalization remains manual.
- Alias types are application-controlled suggestions, not a SQL CHECK
  constraint.
- Inactive products remain selectable so existing links can be retained.
- The Asset dropdown loads the product catalog for manual selection; search or
  autocomplete is not included.
- No import/export, matching, CVE/CPE processing, API, authentication,
  notifications, or dashboard changes are included.
- Forms follow the application's current security posture; CSRF protection is
  not introduced by this sprint.


