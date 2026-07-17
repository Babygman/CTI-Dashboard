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
            CHECK (TimeoutSeconds > 0)
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
        ExternalId NVARCHAR(500) NULL,
        ContentHash CHAR(64) NOT NULL,
        Title NVARCHAR(500) NULL,
        SourceUrl NVARCHAR(1000) NULL,
        PublishedDate DATETIME2 NULL,
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
    CREATE UNIQUE INDEX UX_SourceItems_SourceId_ExternalId
        ON dbo.SourceItems(SourceId, ExternalId)
        WHERE ExternalId IS NOT NULL;
END;
GO
