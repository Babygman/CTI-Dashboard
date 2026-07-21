USE CTIDashboard;
GO

IF OBJECT_ID(N'dbo.Vendors', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Vendors
    (
        VendorId INT IDENTITY(1,1) PRIMARY KEY,

        VendorName NVARCHAR(100) NOT NULL,

        Category NVARCHAR(100),

        Website NVARCHAR(255),

        Enabled BIT DEFAULT 1
    );
END;
GO

IF OBJECT_ID(N'dbo.Threats', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Threats
    (
        ThreatId INT IDENTITY(1,1) PRIMARY KEY,
        Title NVARCHAR(255) NOT NULL,
        VendorId INT NULL,
        Source NVARCHAR(100) NULL,
        Severity NVARCHAR(20) NULL,
        CVE NVARCHAR(50) NULL,
        CVSS DECIMAL(4,1) NULL,
        KEV BIT NOT NULL CONSTRAINT DF_Threats_KEV DEFAULT (0),
        PublishedDate DATETIME2 NULL,
        ReferenceUrl NVARCHAR(1000) NULL,
        Summary NVARCHAR(MAX) NULL,
        Recommendation NVARCHAR(MAX) NULL,
        CreatedAt DATETIME2 NOT NULL
            CONSTRAINT DF_Threats_CreatedAt DEFAULT (SYSUTCDATETIME()),
        ModifiedDate DATETIME2 NULL,

        CONSTRAINT FK_Threats_Vendors
            FOREIGN KEY (VendorId) REFERENCES dbo.Vendors(VendorId),
        CONSTRAINT CK_Threats_CVSS
            CHECK (CVSS IS NULL OR CVSS BETWEEN 0.0 AND 10.0)
    );
END;
GO

IF OBJECT_ID(N'dbo.Sources', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.Sources
    (
        SourceId INT IDENTITY(1,1) PRIMARY KEY,
        SourceName NVARCHAR(200) NOT NULL,
        SourceType NVARCHAR(50) NOT NULL,
        BaseUrl NVARCHAR(1000) NULL,
        FeedUrl NVARCHAR(1000) NULL,
        Enabled BIT NOT NULL
            CONSTRAINT DF_Sources_Enabled DEFAULT (1),
        CollectionIntervalMinutes INT NOT NULL
            CONSTRAINT DF_Sources_CollectionIntervalMinutes DEFAULT (60),
        TimeoutSeconds INT NOT NULL
            CONSTRAINT DF_Sources_TimeoutSeconds DEFAULT (30),
        Priority SMALLINT NOT NULL
            CONSTRAINT DF_Sources_Priority DEFAULT (50),
        LastSuccessfulCollection DATETIME2 NULL,
        LastCollectionStatus NVARCHAR(20) NULL,
        CreatedAt DATETIME2 NOT NULL
            CONSTRAINT DF_Sources_CreatedAt DEFAULT (SYSUTCDATETIME()),
        UpdatedAt DATETIME2 NOT NULL
            CONSTRAINT DF_Sources_UpdatedAt DEFAULT (SYSUTCDATETIME()),

        CONSTRAINT UQ_Sources_SourceName UNIQUE (SourceName),
        CONSTRAINT CK_Sources_CollectionIntervalMinutes
            CHECK (CollectionIntervalMinutes > 0),
        CONSTRAINT CK_Sources_TimeoutSeconds
            CHECK (TimeoutSeconds > 0),
        CONSTRAINT CK_Sources_Priority
            CHECK (Priority BETWEEN 0 AND 100)
    );

    CREATE INDEX IX_Sources_Enabled
        ON dbo.Sources(Enabled);
END;
GO

IF OBJECT_ID(N'dbo.CollectionRuns', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.CollectionRuns
    (
        CollectionRunId BIGINT IDENTITY(1,1) PRIMARY KEY,
        SourceId INT NOT NULL,
        StartedAt DATETIME2 NOT NULL
            CONSTRAINT DF_CollectionRuns_StartedAt DEFAULT (SYSUTCDATETIME()),
        FinishedAt DATETIME2 NULL,
        Status NVARCHAR(20) NOT NULL
            CONSTRAINT DF_CollectionRuns_Status DEFAULT (N'Running'),
        ItemsFetched INT NOT NULL
            CONSTRAINT DF_CollectionRuns_ItemsFetched DEFAULT (0),
        ItemsCreated INT NOT NULL
            CONSTRAINT DF_CollectionRuns_ItemsCreated DEFAULT (0),
        ItemsUpdated INT NOT NULL
            CONSTRAINT DF_CollectionRuns_ItemsUpdated DEFAULT (0),
        ItemsSkipped INT NOT NULL
            CONSTRAINT DF_CollectionRuns_ItemsSkipped DEFAULT (0),
        ErrorMessage NVARCHAR(MAX) NULL,
        WorkerName NVARCHAR(200) NULL,

        CONSTRAINT FK_CollectionRuns_Sources
            FOREIGN KEY (SourceId) REFERENCES dbo.Sources(SourceId),
        CONSTRAINT CK_CollectionRuns_Status
            CHECK (Status IN (N'Running', N'Success', N'Partial', N'Failed')),
        CONSTRAINT CK_CollectionRuns_ItemCounts
            CHECK (
                ItemsFetched >= 0
                AND ItemsCreated >= 0
                AND ItemsUpdated >= 0
                AND ItemsSkipped >= 0
            )
    );

    CREATE INDEX IX_CollectionRuns_SourceId_StartedAt
        ON dbo.CollectionRuns(SourceId, StartedAt);
END;
GO

IF OBJECT_ID(N'dbo.SourceItems', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.SourceItems
    (
        SourceItemId BIGINT IDENTITY(1,1) PRIMARY KEY,
        SourceId INT NOT NULL,
        CollectionRunId BIGINT NULL,
        ExternalId NVARCHAR(500) NULL,
        CVE NVARCHAR(50) NULL,
        ContentHash CHAR(64) NOT NULL,
        Title NVARCHAR(500) NULL,
        SourceUrl NVARCHAR(1000) NULL,
        PublishedDate DATETIME2 NULL,
        SourceModifiedDate DATETIME2 NULL,
        NormalizedMetadata NVARCHAR(MAX) NULL,
        MatchMethod NVARCHAR(30) NULL,
        RawContent NVARCHAR(MAX) NULL,
        ProcessingStatus NVARCHAR(20) NOT NULL
            CONSTRAINT DF_SourceItems_ProcessingStatus DEFAULT (N'Pending'),
        ErrorMessage NVARCHAR(MAX) NULL,
        FirstSeenAt DATETIME2 NOT NULL
            CONSTRAINT DF_SourceItems_FirstSeenAt DEFAULT (SYSUTCDATETIME()),
        LastSeenAt DATETIME2 NOT NULL
            CONSTRAINT DF_SourceItems_LastSeenAt DEFAULT (SYSUTCDATETIME()),
        ThreatId INT NULL,

        CONSTRAINT FK_SourceItems_Sources
            FOREIGN KEY (SourceId) REFERENCES dbo.Sources(SourceId),
        CONSTRAINT FK_SourceItems_CollectionRuns
            FOREIGN KEY (CollectionRunId)
            REFERENCES dbo.CollectionRuns(CollectionRunId),
        CONSTRAINT FK_SourceItems_Threats
            FOREIGN KEY (ThreatId) REFERENCES dbo.Threats(ThreatId),
        CONSTRAINT CK_SourceItems_ProcessingStatus
            CHECK (
                ProcessingStatus IN (
                    N'Pending', N'Processed', N'Duplicate', N'Failed'
                )
            )
    );

    CREATE INDEX IX_SourceItems_SourceId
        ON dbo.SourceItems(SourceId);
    CREATE INDEX IX_SourceItems_ContentHash
        ON dbo.SourceItems(ContentHash);
    CREATE INDEX IX_SourceItems_ProcessingStatus
        ON dbo.SourceItems(ProcessingStatus);
    CREATE INDEX IX_SourceItems_CollectionRunId
        ON dbo.SourceItems(CollectionRunId);
    CREATE INDEX IX_SourceItems_CVE
        ON dbo.SourceItems(CVE)
        WHERE CVE IS NOT NULL;
    CREATE INDEX IX_SourceItems_ThreatId_SourceId
        ON dbo.SourceItems(ThreatId, SourceId)
        INCLUDE (FirstSeenAt, LastSeenAt);
    CREATE UNIQUE INDEX UX_SourceItems_SourceId_ExternalId
        ON dbo.SourceItems(SourceId, ExternalId)
        WHERE ExternalId IS NOT NULL;
END;
GO
IF COL_LENGTH(N'dbo.Threats', N'ModifiedDate') IS NULL
BEGIN
    ALTER TABLE dbo.Threats
        ADD ModifiedDate DATETIME2 NULL;
END;
GO

IF COL_LENGTH(N'dbo.Sources', N'Priority') IS NULL
BEGIN
    ALTER TABLE dbo.Sources
        ADD Priority SMALLINT NOT NULL
            CONSTRAINT DF_Sources_Priority DEFAULT (50) WITH VALUES;
END;
GO

IF NOT EXISTS
(
    SELECT 1
    FROM sys.default_constraints AS dc
    INNER JOIN sys.columns AS c
        ON c.object_id = dc.parent_object_id
        AND c.column_id = dc.parent_column_id
    WHERE dc.parent_object_id = OBJECT_ID(N'dbo.Sources')
      AND c.name = N'Priority'
)
BEGIN
    ALTER TABLE dbo.Sources
        ADD CONSTRAINT DF_Sources_Priority DEFAULT (50) FOR Priority;
END;
GO

IF OBJECT_ID(N'dbo.CK_Sources_Priority', N'C') IS NULL
BEGIN
    ALTER TABLE dbo.Sources WITH CHECK
        ADD CONSTRAINT CK_Sources_Priority
            CHECK (Priority BETWEEN 0 AND 100);
END;
GO

IF COL_LENGTH(N'dbo.SourceItems', N'CollectionRunId') IS NULL
BEGIN
    ALTER TABLE dbo.SourceItems
        ADD CollectionRunId BIGINT NULL;
END;
GO

IF COL_LENGTH(N'dbo.SourceItems', N'CVE') IS NULL
BEGIN
    ALTER TABLE dbo.SourceItems
        ADD CVE NVARCHAR(50) NULL;
END;
GO

IF COL_LENGTH(N'dbo.SourceItems', N'SourceModifiedDate') IS NULL
BEGIN
    ALTER TABLE dbo.SourceItems
        ADD SourceModifiedDate DATETIME2 NULL;
END;
GO

IF COL_LENGTH(N'dbo.SourceItems', N'NormalizedMetadata') IS NULL
BEGIN
    ALTER TABLE dbo.SourceItems
        ADD NormalizedMetadata NVARCHAR(MAX) NULL;
END;
GO

IF COL_LENGTH(N'dbo.SourceItems', N'MatchMethod') IS NULL
BEGIN
    ALTER TABLE dbo.SourceItems
        ADD MatchMethod NVARCHAR(30) NULL;
END;
GO

IF OBJECT_ID(N'dbo.FK_SourceItems_CollectionRuns', N'F') IS NULL
BEGIN
    ALTER TABLE dbo.SourceItems WITH CHECK
        ADD CONSTRAINT FK_SourceItems_CollectionRuns
            FOREIGN KEY (CollectionRunId)
            REFERENCES dbo.CollectionRuns(CollectionRunId);
END;
GO

IF NOT EXISTS
(
    SELECT 1
    FROM sys.indexes
    WHERE object_id = OBJECT_ID(N'dbo.SourceItems')
      AND name = N'IX_SourceItems_CollectionRunId'
)
BEGIN
    CREATE INDEX IX_SourceItems_CollectionRunId
        ON dbo.SourceItems(CollectionRunId);
END;
GO

IF NOT EXISTS
(
    SELECT 1
    FROM sys.indexes
    WHERE object_id = OBJECT_ID(N'dbo.SourceItems')
      AND name = N'IX_SourceItems_CVE'
)
BEGIN
    CREATE INDEX IX_SourceItems_CVE
        ON dbo.SourceItems(CVE)
        WHERE CVE IS NOT NULL;
END;
GO

IF NOT EXISTS
(
    SELECT 1
    FROM sys.indexes
    WHERE object_id = OBJECT_ID(N'dbo.SourceItems')
      AND name = N'IX_SourceItems_ThreatId_SourceId'
)
BEGIN
    CREATE INDEX IX_SourceItems_ThreatId_SourceId
        ON dbo.SourceItems(ThreatId, SourceId)
        INCLUDE (FirstSeenAt, LastSeenAt);
END;
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
