SET NOCOUNT ON;
SET XACT_ABORT ON;

IF OBJECT_ID(N'dbo.CatalogProducts', N'U') IS NULL
    THROW 51000, 'dbo.CatalogProducts does not exist. Apply database/init.sql first.', 1;

IF OBJECT_ID(N'dbo.ProductAliases', N'U') IS NULL
    THROW 51001, 'dbo.ProductAliases does not exist. Apply database/init.sql first.', 1;

BEGIN TRY
    BEGIN TRANSACTION;

    DECLARE @SeedProducts TABLE
    (
        VendorName NVARCHAR(100) NOT NULL,
        ProductName NVARCHAR(200) NOT NULL,
        ProductFamily NVARCHAR(100) NULL,
        TechnologyCategory NVARCHAR(100) NULL,
        Description NVARCHAR(MAX) NULL
    );

    INSERT INTO @SeedProducts
    (
        VendorName,
        ProductName,
        ProductFamily,
        TechnologyCategory,
        Description
    )
    VALUES
        (N'Microsoft', N'Windows Server', N'Windows', N'Server Operating System', N'Microsoft server operating system platform.'),
        (N'Microsoft', N'Windows 11', N'Windows', N'Endpoint Operating System', N'Microsoft enterprise desktop operating system.'),
        (N'Microsoft', N'SQL Server', N'Data Platform', N'Database', N'Microsoft relational database platform.'),
        (N'Microsoft', N'Microsoft 365 Apps', N'Microsoft 365', N'Productivity Suite', N'Microsoft enterprise productivity applications.'),
        (N'Microsoft', N'Exchange Server', N'Exchange', N'Email Server', N'Microsoft on-premises messaging and collaboration server.'),
        (N'Microsoft', N'IIS', N'Windows Server', N'Web Server', N'Microsoft Internet Information Services web server.'),
        (N'Microsoft', N'Edge', N'Edge', N'Web Browser', N'Microsoft enterprise web browser.'),
        (N'Microsoft', N'.NET', N'.NET', N'Application Runtime', N'Microsoft application framework and runtime.'),
        (N'Microsoft', N'Active Directory', N'Identity', N'Identity and Access Management', N'Microsoft directory and identity service.'),

        (N'Fortinet', N'FortiGate', N'FortiGate', N'Firewall', N'Fortinet next-generation firewall appliance family.'),
        (N'Fortinet', N'FortiManager', N'Fortinet Management', N'Network Security Management', N'Centralized management platform for Fortinet devices.'),
        (N'Fortinet', N'FortiAnalyzer', N'Fortinet Analytics', N'Security Analytics', N'Fortinet logging, analytics, and reporting platform.'),

        (N'Cisco', N'IOS XE', N'Cisco IOS', N'Network Operating System', N'Cisco enterprise network operating system.'),
        (N'Cisco', N'ASA', N'Cisco ASA', N'Firewall', N'Cisco Adaptive Security Appliance firewall platform.'),
        (N'Cisco', N'Firepower', N'Cisco Secure Firewall', N'Firewall', N'Cisco threat defense and secure firewall platform.'),
        (N'Cisco', N'Catalyst Switches', N'Cisco Catalyst', N'Network Switching', N'Cisco enterprise switching platform.'),

        (N'Broadcom VMware', N'ESXi', N'VMware vSphere', N'Hypervisor', N'VMware bare-metal enterprise hypervisor.'),
        (N'Broadcom VMware', N'vCenter Server', N'VMware vSphere', N'Virtualization Management', N'Central management server for VMware vSphere.'),
        (N'Broadcom VMware', N'VMware Tools', N'VMware vSphere', N'Guest Tools', N'Guest operating system tools for VMware virtual machines.'),

        (N'Veeam', N'Backup & Replication', N'Veeam Data Platform', N'Backup and Recovery', N'Enterprise backup, replication, and recovery platform.'),
        (N'Veeam', N'Veeam Agent for Microsoft Windows', N'Veeam Agents', N'Endpoint Backup', N'Backup agent for Microsoft Windows systems.'),

        (N'Red Hat', N'Red Hat Enterprise Linux', N'Enterprise Linux', N'Server Operating System', N'Red Hat enterprise Linux distribution.'),
        (N'Linux', N'Linux Kernel', N'Linux', N'Operating System Kernel', N'Linux operating system kernel.'),
        (N'OpenBSD', N'OpenSSH', N'OpenSSH', N'Remote Access', N'Secure Shell implementation used for remote administration.'),
        (N'OpenSSL Project', N'OpenSSL', N'OpenSSL', N'Cryptographic Library', N'Open-source TLS and cryptography toolkit.'),

        (N'Apache', N'HTTP Server', N'Apache HTTP Server', N'Web Server', N'Apache open-source HTTP web server.'),
        (N'Apache', N'Tomcat', N'Apache Tomcat', N'Application Server', N'Apache Java servlet and application server.'),

        (N'Google', N'Chrome', N'Chromium', N'Web Browser', N'Google enterprise web browser.'),
        (N'Mozilla', N'Firefox', N'Firefox', N'Web Browser', N'Mozilla web browser.'),
        (N'Adobe', N'Acrobat Reader', N'Acrobat', N'Document Viewer', N'Adobe PDF document reader.'),

        (N'Oracle', N'Java', N'Java', N'Application Runtime', N'Oracle Java platform and runtime.'),
        (N'Oracle', N'Oracle Database', N'Oracle Database', N'Database', N'Oracle enterprise relational database platform.'),
        (N'Oracle', N'MySQL', N'MySQL', N'Database', N'Oracle MySQL relational database platform.'),

        (N'Python Software Foundation', N'Python', N'Python', N'Application Runtime', N'Python programming language runtime.'),
        (N'Git Project', N'Git', N'Git', N'Version Control', N'Distributed source-control system.'),
        (N'OpenJS Foundation', N'Node.js', N'Node.js', N'Application Runtime', N'Server-side JavaScript runtime.'),
        (N'F5 NGINX', N'Nginx', N'NGINX', N'Web Server', N'NGINX web server and reverse proxy.'),
        (N'PostgreSQL Global Development Group', N'PostgreSQL', N'PostgreSQL', N'Database', N'Open-source relational database platform.');

    IF EXISTS
    (
        SELECT 1
        FROM @SeedProducts
        GROUP BY
            LOWER(LTRIM(RTRIM(VendorName))),
            LOWER(LTRIM(RTRIM(ProductName)))
        HAVING COUNT(*) > 1
    )
        THROW 51002, 'Seed contains duplicate VendorName and ProductName pairs.', 1;

    IF EXISTS
    (
        SELECT 1
        FROM dbo.CatalogProducts AS cp
        INNER JOIN @SeedProducts AS seed
            ON LOWER(LTRIM(RTRIM(cp.VendorName))) = LOWER(LTRIM(RTRIM(seed.VendorName)))
           AND LOWER(LTRIM(RTRIM(cp.ProductName))) = LOWER(LTRIM(RTRIM(seed.ProductName)))
        GROUP BY
            LOWER(LTRIM(RTRIM(cp.VendorName))),
            LOWER(LTRIM(RTRIM(cp.ProductName)))
        HAVING COUNT(*) > 1
    )
        THROW 51003, 'Existing CatalogProducts contains ambiguous case-insensitive matches.', 1;

    DECLARE @ProductResults TABLE
    (
        VendorName NVARCHAR(100) NOT NULL,
        ProductName NVARCHAR(200) NOT NULL,
        Outcome NVARCHAR(20) NOT NULL
    );

    INSERT INTO @ProductResults (VendorName, ProductName, Outcome)
    SELECT
        seed.VendorName,
        seed.ProductName,
        CASE
            WHEN cp.CatalogProductId IS NULL THEN N'Inserted'
            WHEN cp.Active = 0 THEN N'Reactivated'
            WHEN cp.VendorName COLLATE Latin1_General_100_BIN2 <> seed.VendorName COLLATE Latin1_General_100_BIN2
              OR cp.ProductName COLLATE Latin1_General_100_BIN2 <> seed.ProductName COLLATE Latin1_General_100_BIN2
              OR ISNULL(cp.ProductFamily, N'') <> ISNULL(seed.ProductFamily, N'')
              OR ISNULL(cp.TechnologyCategory, N'') <> ISNULL(seed.TechnologyCategory, N'')
              OR ISNULL(cp.Description, N'') <> ISNULL(seed.Description, N'')
                THEN N'Updated'
            ELSE N'Unchanged'
        END
    FROM @SeedProducts AS seed
    LEFT JOIN dbo.CatalogProducts AS cp
        ON LOWER(LTRIM(RTRIM(cp.VendorName))) = LOWER(LTRIM(RTRIM(seed.VendorName)))
       AND LOWER(LTRIM(RTRIM(cp.ProductName))) = LOWER(LTRIM(RTRIM(seed.ProductName)));

    UPDATE cp
    SET
        VendorName = seed.VendorName,
        ProductName = seed.ProductName,
        ProductFamily = seed.ProductFamily,
        TechnologyCategory = seed.TechnologyCategory,
        Description = seed.Description,
        Active = 1,
        UpdatedAt = SYSUTCDATETIME()
    FROM dbo.CatalogProducts AS cp
    INNER JOIN @SeedProducts AS seed
        ON LOWER(LTRIM(RTRIM(cp.VendorName))) = LOWER(LTRIM(RTRIM(seed.VendorName)))
       AND LOWER(LTRIM(RTRIM(cp.ProductName))) = LOWER(LTRIM(RTRIM(seed.ProductName)))
    WHERE cp.Active = 0
       OR cp.VendorName COLLATE Latin1_General_100_BIN2 <> seed.VendorName COLLATE Latin1_General_100_BIN2
       OR cp.ProductName COLLATE Latin1_General_100_BIN2 <> seed.ProductName COLLATE Latin1_General_100_BIN2
       OR ISNULL(cp.ProductFamily, N'') <> ISNULL(seed.ProductFamily, N'')
       OR ISNULL(cp.TechnologyCategory, N'') <> ISNULL(seed.TechnologyCategory, N'')
       OR ISNULL(cp.Description, N'') <> ISNULL(seed.Description, N'');

    INSERT INTO dbo.CatalogProducts
    (
        VendorName,
        ProductName,
        ProductFamily,
        TechnologyCategory,
        Description,
        Active
    )
    SELECT
        seed.VendorName,
        seed.ProductName,
        seed.ProductFamily,
        seed.TechnologyCategory,
        seed.Description,
        1
    FROM @SeedProducts AS seed
    WHERE NOT EXISTS
    (
        SELECT 1
        FROM dbo.CatalogProducts AS cp WITH (UPDLOCK, HOLDLOCK)
        WHERE LOWER(LTRIM(RTRIM(cp.VendorName))) = LOWER(LTRIM(RTRIM(seed.VendorName)))
          AND LOWER(LTRIM(RTRIM(cp.ProductName))) = LOWER(LTRIM(RTRIM(seed.ProductName)))
    );

    DECLARE @SeedAliases TABLE
    (
        VendorName NVARCHAR(100) NOT NULL,
        ProductName NVARCHAR(200) NOT NULL,
        Alias NVARCHAR(200) NOT NULL,
        AliasType NVARCHAR(50) NULL
    );

    INSERT INTO @SeedAliases
    (
        VendorName,
        ProductName,
        Alias,
        AliasType
    )
    VALUES
        (N'Microsoft', N'Windows Server', N'Microsoft Windows Server', N'CommonName'),
        (N'Microsoft', N'Windows Server', N'Windows Server 2016', N'OperatingSystem'),
        (N'Microsoft', N'Windows Server', N'Windows Server 2019', N'OperatingSystem'),
        (N'Microsoft', N'Windows Server', N'Windows Server 2022', N'OperatingSystem'),
        (N'Microsoft', N'Windows Server', N'Windows Server 2025', N'OperatingSystem'),
        (N'Microsoft', N'Windows 11', N'Microsoft Windows 11', N'OperatingSystem'),
        (N'Microsoft', N'SQL Server', N'Microsoft SQL Server', N'CommonName'),
        (N'Microsoft', N'SQL Server', N'SQL Server 2019', N'ProductName'),
        (N'Microsoft', N'SQL Server', N'SQL Server 2022', N'ProductName'),
        (N'Microsoft', N'Microsoft 365 Apps', N'Microsoft Office', N'CommonName'),
        (N'Microsoft', N'Microsoft 365 Apps', N'Office 365', N'CommonName'),
        (N'Microsoft', N'Microsoft 365 Apps', N'Microsoft 365', N'CommonName'),
        (N'Microsoft', N'Exchange Server', N'Microsoft Exchange Server', N'CommonName'),
        (N'Microsoft', N'IIS', N'Microsoft IIS', N'CommonName'),
        (N'Microsoft', N'IIS', N'Internet Information Services', N'CommonName'),
        (N'Microsoft', N'Edge', N'Microsoft Edge', N'CommonName'),
        (N'Microsoft', N'Edge', N'Edge Chromium', N'CommonName'),
        (N'Microsoft', N'.NET', N'Microsoft .NET', N'CommonName'),
        (N'Microsoft', N'.NET', N'.NET Framework', N'Family'),
        (N'Microsoft', N'Active Directory', N'Microsoft Active Directory', N'CommonName'),
        (N'Microsoft', N'Active Directory', N'AD DS', N'CommonName'),

        (N'Fortinet', N'FortiGate', N'Fortigate', N'CommonName'),
        (N'Fortinet', N'FortiGate', N'FortiOS', N'OperatingSystem'),
        (N'Fortinet', N'FortiManager', N'Fortinet FortiManager', N'CommonName'),
        (N'Fortinet', N'FortiAnalyzer', N'Fortinet FortiAnalyzer', N'CommonName'),

        (N'Cisco', N'IOS XE', N'Cisco IOS XE', N'CommonName'),
        (N'Cisco', N'ASA', N'Cisco ASA', N'CommonName'),
        (N'Cisco', N'Firepower', N'Cisco Firepower', N'CommonName'),
        (N'Cisco', N'Catalyst Switches', N'Cisco Catalyst', N'Family'),

        (N'Broadcom VMware', N'ESXi', N'VMware ESXi', N'CommonName'),
        (N'Broadcom VMware', N'vCenter Server', N'VMware vCenter Server', N'CommonName'),
        (N'Broadcom VMware', N'VMware Tools', N'VMware guest tools', N'CommonName'),

        (N'Veeam', N'Backup & Replication', N'Veeam Backup & Replication', N'CommonName'),
        (N'Veeam', N'Veeam Agent for Microsoft Windows', N'Veeam Agent Windows', N'CommonName'),

        (N'Red Hat', N'Red Hat Enterprise Linux', N'RHEL', N'CommonName'),
        (N'Linux', N'Linux Kernel', N'Linux', N'CommonName'),
        (N'OpenBSD', N'OpenSSH', N'Open SSH', N'CommonName'),
        (N'Apache', N'HTTP Server', N'Apache HTTP Server', N'CommonName'),
        (N'Apache', N'HTTP Server', N'Apache HTTPD', N'CommonName'),
        (N'Apache', N'HTTP Server', N'httpd', N'CommonName'),
        (N'Apache', N'Tomcat', N'Apache Tomcat', N'CommonName'),
        (N'Google', N'Chrome', N'Google Chrome', N'CommonName'),
        (N'Mozilla', N'Firefox', N'Mozilla Firefox', N'CommonName'),
        (N'Adobe', N'Acrobat Reader', N'Adobe Reader', N'CommonName'),
        (N'Adobe', N'Acrobat Reader', N'Adobe Acrobat Reader', N'CommonName'),
        (N'Oracle', N'Java', N'Oracle Java', N'CommonName'),
        (N'Oracle', N'Java', N'Java SE', N'Family'),
        (N'Oracle', N'Oracle Database', N'Oracle DB', N'CommonName'),
        (N'Oracle', N'MySQL', N'Oracle MySQL', N'CommonName'),
        (N'Python Software Foundation', N'Python', N'Python 3', N'ProductName'),
        (N'Git Project', N'Git', N'Git SCM', N'CommonName'),
        (N'OpenJS Foundation', N'Node.js', N'NodeJS', N'CommonName'),
        (N'F5 NGINX', N'Nginx', N'NGINX', N'CommonName'),
        (N'PostgreSQL Global Development Group', N'PostgreSQL', N'Postgres', N'CommonName');

    IF EXISTS
    (
        SELECT 1
        FROM @SeedAliases
        GROUP BY
            LOWER(LTRIM(RTRIM(VendorName))),
            LOWER(LTRIM(RTRIM(ProductName))),
            LOWER(LTRIM(RTRIM(Alias)))
        HAVING COUNT(*) > 1
    )
        THROW 51004, 'Seed contains duplicate aliases for the same product.', 1;

    IF EXISTS
    (
        SELECT 1
        FROM @SeedAliases
        GROUP BY LOWER(LTRIM(RTRIM(Alias)))
        HAVING COUNT(*) > 1
    )
        THROW 51005, 'Seed aliases are ambiguous across products.', 1;

    IF EXISTS
    (
        SELECT 1
        FROM @SeedAliases AS seed
        INNER JOIN dbo.CatalogProducts AS target
            ON LOWER(LTRIM(RTRIM(target.VendorName))) = LOWER(LTRIM(RTRIM(seed.VendorName)))
           AND LOWER(LTRIM(RTRIM(target.ProductName))) = LOWER(LTRIM(RTRIM(seed.ProductName)))
        INNER JOIN dbo.ProductAliases AS existing_alias
            ON LOWER(LTRIM(RTRIM(existing_alias.Alias))) = LOWER(LTRIM(RTRIM(seed.Alias)))
           AND existing_alias.CatalogProductId <> target.CatalogProductId
    )
        THROW 51006, 'An existing alias maps to a different product and would make normalization ambiguous.', 1;

    IF EXISTS
    (
        SELECT 1
        FROM @SeedAliases AS seed
        INNER JOIN dbo.CatalogProducts AS target
            ON LOWER(LTRIM(RTRIM(target.VendorName))) = LOWER(LTRIM(RTRIM(seed.VendorName)))
           AND LOWER(LTRIM(RTRIM(target.ProductName))) = LOWER(LTRIM(RTRIM(seed.ProductName)))
        INNER JOIN dbo.ProductAliases AS existing_alias
            ON existing_alias.CatalogProductId = target.CatalogProductId
           AND LOWER(LTRIM(RTRIM(existing_alias.Alias))) = LOWER(LTRIM(RTRIM(seed.Alias)))
        GROUP BY
            target.CatalogProductId,
            LOWER(LTRIM(RTRIM(seed.Alias)))
        HAVING COUNT(*) > 1
    )
        THROW 51007, 'Existing ProductAliases contains ambiguous case-insensitive matches.', 1;

    IF EXISTS
    (
        SELECT 1
        FROM @SeedAliases AS seed
        INNER JOIN dbo.CatalogProducts AS target
            ON LOWER(LTRIM(RTRIM(target.VendorName))) = LOWER(LTRIM(RTRIM(seed.VendorName)))
           AND LOWER(LTRIM(RTRIM(target.ProductName))) = LOWER(LTRIM(RTRIM(seed.ProductName)))
        INNER JOIN dbo.CatalogProducts AS conflicting_product
            ON LOWER(LTRIM(RTRIM(conflicting_product.ProductName))) = LOWER(LTRIM(RTRIM(seed.Alias)))
           AND conflicting_product.CatalogProductId <> target.CatalogProductId
           AND conflicting_product.Active = 1
    )
        THROW 51008, 'A seed alias conflicts with a different active canonical product name.', 1;
    DECLARE @AliasResults TABLE
    (
        Alias NVARCHAR(200) NOT NULL,
        Outcome NVARCHAR(20) NOT NULL
    );

    INSERT INTO @AliasResults (Alias, Outcome)
    SELECT
        seed.Alias,
        CASE
            WHEN existing_alias.ProductAliasId IS NULL THEN N'Inserted'
            WHEN existing_alias.Active = 0 THEN N'Reactivated'
            WHEN ISNULL(existing_alias.AliasType, N'') <> ISNULL(seed.AliasType, N'')
              OR existing_alias.Alias COLLATE Latin1_General_100_BIN2 <> seed.Alias COLLATE Latin1_General_100_BIN2
                THEN N'Updated'
            ELSE N'Unchanged'
        END
    FROM @SeedAliases AS seed
    INNER JOIN dbo.CatalogProducts AS target
        ON LOWER(LTRIM(RTRIM(target.VendorName))) = LOWER(LTRIM(RTRIM(seed.VendorName)))
       AND LOWER(LTRIM(RTRIM(target.ProductName))) = LOWER(LTRIM(RTRIM(seed.ProductName)))
    LEFT JOIN dbo.ProductAliases AS existing_alias
        ON existing_alias.CatalogProductId = target.CatalogProductId
       AND LOWER(LTRIM(RTRIM(existing_alias.Alias))) = LOWER(LTRIM(RTRIM(seed.Alias)));

    UPDATE existing_alias
    SET
        Alias = seed.Alias,
        AliasType = seed.AliasType,
        Active = 1
    FROM dbo.ProductAliases AS existing_alias
    INNER JOIN dbo.CatalogProducts AS target
        ON existing_alias.CatalogProductId = target.CatalogProductId
    INNER JOIN @SeedAliases AS seed
        ON LOWER(LTRIM(RTRIM(target.VendorName))) = LOWER(LTRIM(RTRIM(seed.VendorName)))
       AND LOWER(LTRIM(RTRIM(target.ProductName))) = LOWER(LTRIM(RTRIM(seed.ProductName)))
       AND LOWER(LTRIM(RTRIM(existing_alias.Alias))) = LOWER(LTRIM(RTRIM(seed.Alias)))
    WHERE existing_alias.Active = 0
       OR ISNULL(existing_alias.AliasType, N'') <> ISNULL(seed.AliasType, N'')
       OR existing_alias.Alias COLLATE Latin1_General_100_BIN2 <> seed.Alias COLLATE Latin1_General_100_BIN2;

    INSERT INTO dbo.ProductAliases
    (
        CatalogProductId,
        Alias,
        AliasType,
        Active
    )
    SELECT
        target.CatalogProductId,
        seed.Alias,
        seed.AliasType,
        1
    FROM @SeedAliases AS seed
    INNER JOIN dbo.CatalogProducts AS target
        ON LOWER(LTRIM(RTRIM(target.VendorName))) = LOWER(LTRIM(RTRIM(seed.VendorName)))
       AND LOWER(LTRIM(RTRIM(target.ProductName))) = LOWER(LTRIM(RTRIM(seed.ProductName)))
    WHERE NOT EXISTS
    (
        SELECT 1
        FROM dbo.ProductAliases AS existing_alias WITH (UPDLOCK, HOLDLOCK)
        WHERE existing_alias.CatalogProductId = target.CatalogProductId
          AND LOWER(LTRIM(RTRIM(existing_alias.Alias))) = LOWER(LTRIM(RTRIM(seed.Alias)))
    );

    COMMIT TRANSACTION;

    SELECT
        SUM(CASE WHEN Outcome = N'Inserted' THEN 1 ELSE 0 END) AS Inserted,
        SUM(CASE WHEN Outcome = N'Updated' THEN 1 ELSE 0 END) AS Updated,
        SUM(CASE WHEN Outcome = N'Reactivated' THEN 1 ELSE 0 END) AS Reactivated,
        SUM(CASE WHEN Outcome = N'Unchanged' THEN 1 ELSE 0 END) AS Unchanged
    FROM @ProductResults;

    SELECT
        SUM(CASE WHEN Outcome = N'Inserted' THEN 1 ELSE 0 END) AS AliasesInserted,
        SUM(CASE WHEN Outcome = N'Updated' THEN 1 ELSE 0 END) AS AliasesUpdated,
        SUM(CASE WHEN Outcome = N'Reactivated' THEN 1 ELSE 0 END) AS AliasesReactivated,
        SUM(CASE WHEN Outcome = N'Unchanged' THEN 1 ELSE 0 END) AS AliasesUnchanged
    FROM @AliasResults;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0
        ROLLBACK TRANSACTION;
    THROW;
END CATCH;


