# CTI Dashboard Proposed Data Model

Status: logical and physical design proposal. It does not alter the current database. Exact names and migrations must be validated against the deployed SQL Server schema before implementation.

## 1. Conventions

- SQL Server schema: `dbo` unless deployment standards require a dedicated application schema.
- Primary keys: existing key names and types are retained. New high-volume operational tables should use `BIGINT IDENTITY`; small reference tables may use `INT IDENTITY`.
- Timestamps: UTC `DATETIME2(3)`. `CreatedAt` is immutable; `UpdatedAt` changes on material updates. Use a database UTC default such as `SYSUTCDATETIME()` where appropriate.
- Boolean values: `BIT NOT NULL` with explicit defaults.
- Status values: `NVARCHAR(30)` plus a `CHECK` constraint. Application enums mirror the database values.
- Money/token/cost estimates: use fixed precision decimal, not floating point.
- URLs: `NVARCHAR(1000)` unless measured provider data requires a separately reviewed limit.
- Hashes: SHA-256 stored as `BINARY(32)` where possible. Canonical keys may be bounded `NVARCHAR` when human readability helps.
- Foreign keys default to `ON DELETE NO ACTION`. Historical evidence is disabled or retained, not cascade-deleted.
- Every index is reviewed against actual SQL Server query plans and Express storage constraints before production.
- Optimistic concurrency: mutable administrative tables should include `RowVersion ROWVERSION` where it improves conflict handling.

## 2. Existing tables retained

### `Vendors`

Existing schema remains unchanged.

| Column | Type | Rules |
|---|---|---|
| `VendorId` | `INT IDENTITY` | Primary key |
| `VendorName` | `NVARCHAR(100)` | Required |
| `Category` | `NVARCHAR(100)` | Nullable |
| `Website` | `NVARCHAR(255)` | Nullable |
| `Enabled` | `BIT` | Existing behavior retained |

Recommended future index, subject to current duplicate policy: nonclustered index on normalized/searchable `VendorName`. Do not add a case-insensitive unique constraint until existing data has been audited, because the current application performs duplicate checking in code and production collation may vary.

### `Threats`

The deployed table remains the canonical threat table. Its current columns and SQLAlchemy behavior are retained:

| Column | Role |
|---|---|
| `ThreatId` | Primary key |
| `Title` | Required title |
| `VendorId` | Nullable FK to `Vendors.VendorId` |
| `Source` | Existing display/source field |
| `Severity` | Existing severity |
| `CVE` | Existing primary/display CVE |
| `CVSS` | Existing score, constrained by application to 0.0–10.0 |
| `KEV` | Existing boolean |
| `PublishedDate` | Existing publication timestamp/date |
| `ReferenceUrl` | Existing reference URL |
| `Summary` | Existing summary |
| `Recommendation` | Existing recommendation |
| `CreatedAt` | Existing creation timestamp |

Recommended additive columns in a future reviewed migration:

| Column | Type | Rules / purpose |
|---|---|---|
| `CanonicalKey` | `NVARCHAR(300)` | Nullable during backfill; deterministic duplicate key |
| `Origin` | `NVARCHAR(20)` | `Manual` or `Collected` |
| `FirstSeenAt` | `DATETIME2(3)` | First observation time |
| `LastSeenAt` | `DATETIME2(3)` | Latest supporting observation time |
| `UpdatedAt` | `DATETIME2(3)` | Latest material canonical update |
| `IsSuppressed` | `BIT` | Optional, owner-approved alternative to deleting imported threats |
| `RowVersion` | `ROWVERSION` | Optional concurrency token |

Proposed indexes after data cleanup/backfill:

- Filtered unique index `UX_Threats_CanonicalKey` on `CanonicalKey WHERE CanonicalKey IS NOT NULL`.
- Index on `(PublishedDate DESC, ThreatId DESC)` including dashboard columns.
- Index on `(Severity, PublishedDate DESC)`.
- Index on `(VendorId, PublishedDate DESC)`.
- Filtered index on `(PublishedDate DESC) WHERE KEV = 1` if KEV queries justify it.

The existing single `CVE` field remains for compatibility/display. `ThreatCVEs` becomes the normalized indexed representation when an advisory contains multiple CVEs.

## 3. Collection and provenance

### `Sources`

One row per configured source endpoint or provider stream.

| Column | Type | Rules |
|---|---|---|
| `SourceId` | `INT IDENTITY` | PK |
| `SourceKey` | `NVARCHAR(100)` | Required, unique, stable configuration key |
| `Name` | `NVARCHAR(200)` | Required |
| `SourceType` | `NVARCHAR(30)` | Required; `CisaKev`, `Nvd`, `Rss`, `Microsoft`, `Fortinet`, `Cisco`, `Veeam`, `Broadcom` |
| `EndpointUrl` | `NVARCHAR(1000)` | Required, validated/allowlisted |
| `Enabled` | `BIT` | Required, default 1 |
| `ScheduleMinutes` | `INT` | Required, bounded check, for example 5–10080 |
| `CursorValue` | `NVARCHAR(1000)` | Nullable opaque provider cursor/watermark |
| `ETag` | `NVARCHAR(500)` | Nullable |
| `LastModifiedValue` | `NVARCHAR(200)` | Nullable HTTP conditional value |
| `LastAttemptAt` | `DATETIME2(3)` | Nullable |
| `LastSuccessAt` | `DATETIME2(3)` | Nullable |
| `ConsecutiveFailures` | `INT` | Required, default 0, nonnegative |
| `Status` | `NVARCHAR(30)` | `Enabled`, `Disabled`, `Unhealthy` |
| `NextRunAt` | `DATETIME2(3)` | Required for due-source lookup |
| `LockedUntil` | `DATETIME2(3)` | Nullable lease expiry |
| `WorkerId` | `NVARCHAR(100)` | Nullable lease owner |
| `CreatedAt` | `DATETIME2(3)` | Required |
| `UpdatedAt` | `DATETIME2(3)` | Required |
| `RowVersion` | `ROWVERSION` | Concurrency token |

Constraints/indexes:

- `UQ_Sources_SourceKey (SourceKey)`.
- Index `IX_Sources_Due (Enabled, NextRunAt)` including lease/status fields.
- Check `ScheduleMinutes > 0`, `ConsecutiveFailures >= 0`.
- Endpoint and non-secret parameters are stored here; credentials/API keys are not.

### `CollectionRuns`

One row per attempted source execution.

| Column | Type | Rules |
|---|---|---|
| `CollectionRunId` | `BIGINT IDENTITY` | PK |
| `SourceId` | `INT` | Required FK to `Sources` |
| `Status` | `NVARCHAR(30)` | `Running`, `Succeeded`, `Partial`, `Failed`, `TimedOut` |
| `TriggerType` | `NVARCHAR(20)` | `Scheduled`, `Manual`, `Replay` |
| `CorrelationId` | `UNIQUEIDENTIFIER` | Required |
| `WorkerId` | `NVARCHAR(100)` | Required |
| `StartedAt` | `DATETIME2(3)` | Required |
| `CompletedAt` | `DATETIME2(3)` | Nullable while running |
| `ItemsFetched` | `INT` | Required, default 0 |
| `ItemsCreated` | `INT` | Required, default 0 |
| `ItemsUpdated` | `INT` | Required, default 0 |
| `ItemsDuplicate` | `INT` | Required, default 0 |
| `ItemsRejected` | `INT` | Required, default 0 |
| `ItemsFailed` | `INT` | Required, default 0 |
| `HttpStatusCode` | `INT` | Nullable |
| `ErrorCategory` | `NVARCHAR(30)` | Nullable controlled category |
| `ErrorMessage` | `NVARCHAR(2000)` | Nullable, sanitized |
| `CursorBefore` | `NVARCHAR(1000)` | Nullable |
| `CursorAfter` | `NVARCHAR(1000)` | Nullable |
| `CreatedAt` | `DATETIME2(3)` | Required |

Constraints/indexes:

- FK `SourceId -> Sources.SourceId`, `NO ACTION`.
- Index `(SourceId, StartedAt DESC)` including status/counts/duration fields.
- Index `(Status, StartedAt DESC)` for health and stale-run queries.
- Nonnegative checks on all item counts.

### `SourceItems`

An immutable or versioned source observation captured before canonical threat resolution.

| Column | Type | Rules |
|---|---|---|
| `SourceItemId` | `BIGINT IDENTITY` | PK |
| `SourceId` | `INT` | Required FK to `Sources` |
| `CollectionRunId` | `BIGINT` | Required FK to `CollectionRuns` |
| `ExternalId` | `NVARCHAR(500)` | Nullable stable provider identifier |
| `ExternalVersion` | `NVARCHAR(200)` | Nullable provider version/update marker |
| `CanonicalUrl` | `NVARCHAR(1000)` | Nullable |
| `CanonicalUrlHash` | `BINARY(32)` | Nullable |
| `Title` | `NVARCHAR(500)` | Nullable source title |
| `PublishedAt` | `DATETIME2(3)` | Nullable |
| `ModifiedAt` | `DATETIME2(3)` | Nullable |
| `RetrievedAt` | `DATETIME2(3)` | Required |
| `ContentHash` | `BINARY(32)` | Required normalized payload hash |
| `PayloadJson` | `NVARCHAR(MAX)` | Nullable raw/sanitized payload, retention-controlled |
| `PayloadLocation` | `NVARCHAR(1000)` | Nullable alternative archive reference |
| `Status` | `NVARCHAR(30)` | `New`, `Normalized`, `Duplicate`, `Rejected`, `Failed` |
| `ErrorCategory` | `NVARCHAR(30)` | Nullable |
| `ErrorMessage` | `NVARCHAR(2000)` | Nullable, sanitized |
| `CreatedAt` | `DATETIME2(3)` | Required |
| `UpdatedAt` | `DATETIME2(3)` | Required |

Constraints/indexes:

- FKs to `Sources` and `CollectionRuns`, both `NO ACTION`.
- Filtered unique index `(SourceId, ExternalId, ExternalVersion) WHERE ExternalId IS NOT NULL`; if versions are not meaningful, normalize `ExternalVersion` to a stable sentinel.
- Unique index `(SourceId, ContentHash)` as the content-level fallback, subject to source behavior testing.
- Index `(CollectionRunId, Status)` for run diagnosis.
- Index `(SourceId, PublishedAt DESC)` for source history.

If source updates must be preserved, insert a new row for a new content hash/version rather than overwrite payload evidence. Retention can remove `PayloadJson` later while preserving identity, hashes, URLs, and relationships.

### `ThreatSources`

Many-to-many provenance link between canonical threats and source observations.

| Column | Type | Rules |
|---|---|---|
| `ThreatSourceId` | `BIGINT IDENTITY` | PK |
| `ThreatId` | Existing Threat PK type | Required FK to `Threats` |
| `SourceItemId` | `BIGINT` | Required FK to `SourceItems` |
| `RelationshipType` | `NVARCHAR(30)` | `Primary`, `Supporting`, `Enrichment`, `Manual` |
| `FirstLinkedAt` | `DATETIME2(3)` | Required |
| `LastConfirmedAt` | `DATETIME2(3)` | Required |
| `CreatedAt` | `DATETIME2(3)` | Required |

Constraints/indexes:

- Unique `(ThreatId, SourceItemId)`.
- Index `(SourceItemId, ThreatId)` for reverse provenance lookup.
- FKs use `NO ACTION`; provenance is not cascade-deleted.

### `ThreatCVEs`

Normalized many-CVE representation.

| Column | Type | Rules |
|---|---|---|
| `ThreatCVEId` | `BIGINT IDENTITY` | PK |
| `ThreatId` | Existing Threat PK type | Required FK to `Threats` |
| `CVE` | `VARCHAR(20)` | Required uppercase validated value |
| `IsPrimary` | `BIT` | Required, default 0 |
| `CreatedAt` | `DATETIME2(3)` | Required |

Constraints/indexes:

- Unique `(ThreatId, CVE)`.
- Index `(CVE, ThreatId)` for CVE resolution and filtering.
- At most one primary CVE per threat should be enforced by a filtered unique index on `ThreatId WHERE IsPrimary = 1`.

### `VendorMappings`

Maps provider terminology to the existing normalized vendor dimension.

| Column | Type | Rules |
|---|---|---|
| `VendorMappingId` | `INT IDENTITY` | PK |
| `SourceId` | `INT` | Nullable FK; null means global mapping |
| `ExternalVendorName` | `NVARCHAR(200)` | Required original/recognized name |
| `NormalizedExternalName` | `NVARCHAR(200)` | Required normalized lookup value |
| `ProductPattern` | `NVARCHAR(300)` | Nullable bounded pattern, not arbitrary executable regex by default |
| `VendorId` | `INT` | Required FK to `Vendors` |
| `Priority` | `INT` | Required, default 100 |
| `Enabled` | `BIT` | Required, default 1 |
| `CreatedAt` | `DATETIME2(3)` | Required |
| `UpdatedAt` | `DATETIME2(3)` | Required |
| `UpdatedByUserId` | `INT` | Nullable FK to `Users` once identity exists |
| `RowVersion` | `ROWVERSION` | Concurrency token |

Constraints/indexes:

- Unique `(SourceId, NormalizedExternalName, ProductPattern)` with an implementation that handles SQL Server null semantics explicitly.
- Index `(NormalizedExternalName, Enabled, Priority)` including `VendorId`.

### `OrganizationAssets`

Lightweight relevance inventory, not a replacement CMDB.

| Column | Type | Rules |
|---|---|---|
| `OrganizationAssetId` | `INT IDENTITY` | PK |
| `Name` | `NVARCHAR(200)` | Required |
| `VendorId` | `INT` | Nullable FK to `Vendors` |
| `ProductName` | `NVARCHAR(200)` | Required |
| `VersionPattern` | `NVARCHAR(200)` | Nullable |
| `BusinessCriticality` | `NVARCHAR(20)` | `Low`, `Medium`, `High`, `Critical` |
| `Owner` | `NVARCHAR(200)` | Nullable team/contact, not a secret |
| `Enabled` | `BIT` | Required, default 1 |
| `CreatedAt` | `DATETIME2(3)` | Required |
| `UpdatedAt` | `DATETIME2(3)` | Required |
| `RowVersion` | `ROWVERSION` | Concurrency token |

Indexes: `(VendorId, ProductName, Enabled)` and `(Enabled, BusinessCriticality)`. Matching remains advisory unless connected to an authoritative asset/CMDB process.

## 4. AI analysis

### `AIAnalyses`

Stores durable work state and versioned structured output.

| Column | Type | Rules |
|---|---|---|
| `AIAnalysisId` | `BIGINT IDENTITY` | PK |
| `ThreatId` | Existing Threat PK type | Required FK to `Threats` |
| `AnalysisType` | `NVARCHAR(30)` | Required, initially `Core` |
| `Provider` | `NVARCHAR(50)` | Required |
| `Model` | `NVARCHAR(100)` | Required |
| `PromptVersion` | `NVARCHAR(50)` | Required |
| `InputHash` | `BINARY(32)` | Required |
| `Status` | `NVARCHAR(30)` | `Pending`, `InProgress`, `Retry`, `Succeeded`, `Failed`, `Cancelled` |
| `AttemptCount` | `INT` | Required, default 0 |
| `NextAttemptAt` | `DATETIME2(3)` | Nullable |
| `LockedUntil` | `DATETIME2(3)` | Nullable |
| `WorkerId` | `NVARCHAR(100)` | Nullable |
| `SummaryEnglish` | `NVARCHAR(MAX)` | Nullable until success |
| `SummaryThai` | `NVARCHAR(MAX)` | Nullable until success |
| `BusinessImpactEnglish` | `NVARCHAR(MAX)` | Nullable |
| `BusinessImpactThai` | `NVARCHAR(MAX)` | Nullable |
| `RecommendationEnglish` | `NVARCHAR(MAX)` | Nullable |
| `RecommendationThai` | `NVARCHAR(MAX)` | Nullable |
| `AffectedProductsJson` | `NVARCHAR(MAX)` | Nullable, schema-validated JSON |
| `Relevance` | `NVARCHAR(20)` | Nullable; `Unknown`, `Low`, `Medium`, `High` |
| `RelevanceRationaleJson` | `NVARCHAR(MAX)` | Nullable validated JSON |
| `Confidence` | `DECIMAL(5,4)` | Nullable, check 0–1 |
| `WarningsJson` | `NVARCHAR(MAX)` | Nullable validated JSON |
| `InputTokenCount` | `INT` | Nullable, nonnegative |
| `OutputTokenCount` | `INT` | Nullable, nonnegative |
| `EstimatedCost` | `DECIMAL(18,6)` | Nullable, nonnegative |
| `ErrorCategory` | `NVARCHAR(30)` | Nullable |
| `ErrorMessage` | `NVARCHAR(2000)` | Nullable, sanitized |
| `StartedAt` | `DATETIME2(3)` | Nullable |
| `CompletedAt` | `DATETIME2(3)` | Nullable |
| `CreatedAt` | `DATETIME2(3)` | Required |
| `UpdatedAt` | `DATETIME2(3)` | Required |

Constraints/indexes:

- FK to `Threats`, `NO ACTION`.
- Unique `(ThreatId, AnalysisType, Provider, Model, PromptVersion, InputHash)`.
- Work-claim index `(Status, NextAttemptAt, LockedUntil, CreatedAt)` including attempt/provider fields.
- Index `(ThreatId, CompletedAt DESC)` for current/history display.
- Check attempt/token counts and confidence/cost ranges.

A successful row is immutable except for explicitly separated operator annotations. Reanalysis inserts a new version when input, prompt, model, or provider changes.

## 5. Alerts and delivery

### `AlertRules`

| Column | Type | Rules |
|---|---|---|
| `AlertRuleId` | `INT IDENTITY` | PK |
| `Name` | `NVARCHAR(200)` | Required, unique |
| `Enabled` | `BIT` | Required, default 1 |
| `MinimumSeverity` | `NVARCHAR(20)` | Nullable controlled severity |
| `MinimumCVSS` | `DECIMAL(4,1)` | Nullable, check 0.0–10.0 |
| `KEVOnly` | `BIT` | Required, default 0 |
| `VendorId` | `INT` | Nullable FK to `Vendors` |
| `SourceId` | `INT` | Nullable FK to `Sources` |
| `RequireCVE` | `BIT` | Required, default 0 |
| `MinimumRelevance` | `NVARCHAR(20)` | Nullable controlled value |
| `WaitForAI` | `BIT` | Required, default 0 |
| `RuleVersion` | `INT` | Required, starts at 1 |
| `CreatedAt` | `DATETIME2(3)` | Required |
| `UpdatedAt` | `DATETIME2(3)` | Required |
| `CreatedByUserId` | `INT` | Nullable FK to `Users` |
| `UpdatedByUserId` | `INT` | Nullable FK to `Users` |
| `RowVersion` | `ROWVERSION` | Concurrency token |

Indexes: unique `Name`; `(Enabled, MinimumSeverity, KEVOnly)`; optional vendor/source indexes after query review. More complex conditions should use validated JSON interpreted by application code, never executable SQL.

### `AlertRecipients`

| Column | Type | Rules |
|---|---|---|
| `AlertRecipientId` | `INT IDENTITY` | PK |
| `Name` | `NVARCHAR(200)` | Required |
| `EmailAddress` | `NVARCHAR(320)` | Required |
| `NormalizedEmailAddress` | `NVARCHAR(320)` | Required, unique |
| `RecipientType` | `NVARCHAR(20)` | `User`, `Group`, `Mailbox` |
| `Enabled` | `BIT` | Required, default 1 |
| `CreatedAt` | `DATETIME2(3)` | Required |
| `UpdatedAt` | `DATETIME2(3)` | Required |
| `RowVersion` | `ROWVERSION` | Concurrency token |

If recipients vary by rule, add `AlertRuleRecipients(AlertRuleId, AlertRecipientId, CreatedAt)` with composite PK and `NO ACTION` FKs. Otherwise document the simpler all-active-recipient policy.

### `Alerts`

One logical rule match, independent of delivery attempts.

| Column | Type | Rules |
|---|---|---|
| `AlertId` | `BIGINT IDENTITY` | PK |
| `AlertRuleId` | `INT` | Required FK to `AlertRules` |
| `AlertRuleVersion` | `INT` | Required snapshot version |
| `ThreatId` | Existing Threat PK type | Required FK to `Threats` |
| `AIAnalysisId` | `BIGINT` | Nullable FK to `AIAnalyses` |
| `ThreatVersionHash` | `BINARY(32)` | Required alert-relevant state hash |
| `DedupeKey` | `BINARY(32)` | Required unique logical key |
| `Status` | `NVARCHAR(30)` | `Pending`, `Ready`, `Suppressed`, `Sent`, `Partial`, `Failed` |
| `SuppressionReason` | `NVARCHAR(500)` | Nullable |
| `MatchedAt` | `DATETIME2(3)` | Required |
| `CompletedAt` | `DATETIME2(3)` | Nullable |
| `CreatedAt` | `DATETIME2(3)` | Required |
| `UpdatedAt` | `DATETIME2(3)` | Required |

Constraints/indexes:

- Unique `DedupeKey`; alternatively unique `(AlertRuleId, AlertRuleVersion, ThreatId, ThreatVersionHash)`.
- Index `(Status, CreatedAt)` and `(ThreatId, CreatedAt DESC)`.
- Historical rows retain rule version and state hash even if the rule changes.

### `AlertDeliveries`

One recipient delivery plus its retry/lease state.

| Column | Type | Rules |
|---|---|---|
| `AlertDeliveryId` | `BIGINT IDENTITY` | PK |
| `AlertId` | `BIGINT` | Required FK to `Alerts` |
| `AlertRecipientId` | `INT` | Required FK to `AlertRecipients` |
| `ResendOfDeliveryId` | `BIGINT` | Nullable self-FK |
| `DeliverySequence` | `INT` | Required, default 1 |
| `Provider` | `NVARCHAR(30)` | Required, e.g. `Graph` or `SmtpRelay` |
| `Status` | `NVARCHAR(30)` | `Pending`, `InProgress`, `Retry`, `Sent`, `Failed`, `Cancelled` |
| `AttemptCount` | `INT` | Required, default 0 |
| `NextAttemptAt` | `DATETIME2(3)` | Nullable |
| `LockedUntil` | `DATETIME2(3)` | Nullable |
| `WorkerId` | `NVARCHAR(100)` | Nullable |
| `RecipientSnapshot` | `NVARCHAR(320)` | Required immutable destination snapshot |
| `Subject` | `NVARCHAR(500)` | Required rendered subject |
| `BodyHash` | `BINARY(32)` | Required |
| `ProviderMessageId` | `NVARCHAR(500)` | Nullable |
| `ErrorCategory` | `NVARCHAR(30)` | Nullable |
| `ErrorMessage` | `NVARCHAR(2000)` | Nullable, sanitized |
| `LastAttemptAt` | `DATETIME2(3)` | Nullable |
| `SentAt` | `DATETIME2(3)` | Nullable |
| `CreatedAt` | `DATETIME2(3)` | Required |
| `UpdatedAt` | `DATETIME2(3)` | Required |
| `RequestedByUserId` | `INT` | Nullable FK to `Users` for manual resend |

Constraints/indexes:

- Unique `(AlertId, AlertRecipientId, DeliverySequence)`.
- For initial delivery, application/database logic ensures sequence 1 appears once. Resend increments sequence and links lineage.
- Work-claim index `(Status, NextAttemptAt, LockedUntil, CreatedAt)`.
- Index `(AlertRecipientId, CreatedAt DESC)` and filtered/provider message lookup if operationally useful.

## 6. Identity and authorization

### `Users`

Local shadow record; no password fields.

| Column | Type | Rules |
|---|---|---|
| `UserId` | `INT IDENTITY` | PK |
| `EntraTenantId` | `UNIQUEIDENTIFIER` | Required |
| `EntraObjectId` | `UNIQUEIDENTIFIER` | Required stable subject/object identifier |
| `UserPrincipalName` | `NVARCHAR(320)` | Nullable, mutable display/login attribute |
| `Email` | `NVARCHAR(320)` | Nullable |
| `DisplayName` | `NVARCHAR(200)` | Nullable |
| `Status` | `NVARCHAR(20)` | `Active`, `Disabled` |
| `LastLoginAt` | `DATETIME2(3)` | Nullable |
| `CreatedAt` | `DATETIME2(3)` | Required |
| `UpdatedAt` | `DATETIME2(3)` | Required |
| `RowVersion` | `ROWVERSION` | Concurrency token |

Constraints/indexes:

- Unique `(EntraTenantId, EntraObjectId)`.
- Non-unique indexes on `UserPrincipalName` and `Email` for administration; neither is the identity key.

### `Roles`

| Column | Type | Rules |
|---|---|---|
| `RoleId` | `SMALLINT IDENTITY` | PK |
| `RoleName` | `NVARCHAR(50)` | Required, unique; seed `Admin`, `Viewer` |
| `Description` | `NVARCHAR(500)` | Nullable |
| `CreatedAt` | `DATETIME2(3)` | Required |

Role names are code/Entra contract values and are not freely renamed in the UI.

### `UserRoles`

| Column | Type | Rules |
|---|---|---|
| `UserId` | `INT` | PK part, FK to `Users` |
| `RoleId` | `SMALLINT` | PK part, FK to `Roles` |
| `AssignmentSource` | `NVARCHAR(20)` | `Entra`, `Emergency` if approved |
| `AssignedAt` | `DATETIME2(3)` | Required |
| `LastConfirmedAt` | `DATETIME2(3)` | Required |

Composite PK `(UserId, RoleId)` and index `(RoleId, UserId)`. Entra role claims remain authoritative; local rows support audit/query and must not silently grant roles absent from a current valid claim, except through a separately approved emergency process.

## 7. Administration and audit

### `SystemSettings`

Only allowlisted non-secret settings.

| Column | Type | Rules |
|---|---|---|
| `SystemSettingId` | `INT IDENTITY` | PK |
| `SettingKey` | `NVARCHAR(150)` | Required, unique, allowlisted |
| `ValueType` | `NVARCHAR(20)` | `String`, `Integer`, `Decimal`, `Boolean`, `Json` |
| `Value` | `NVARCHAR(MAX)` | Required, validated by registry |
| `Scope` | `NVARCHAR(30)` | Required, e.g. `Collection`, `AI`, `Alerts`, `UI` |
| `Description` | `NVARCHAR(1000)` | Required |
| `IsEnabled` | `BIT` | Required, default 1 |
| `Version` | `INT` | Required, incremented on change |
| `UpdatedByUserId` | `INT` | Required FK to `Users` once auth is active |
| `CreatedAt` | `DATETIME2(3)` | Required |
| `UpdatedAt` | `DATETIME2(3)` | Required |
| `RowVersion` | `ROWVERSION` | Concurrency token |

Constraints/indexes: unique `SettingKey`; index `(Scope, IsEnabled)`. Secrets, API keys, tokens, private keys, passwords, and connection strings are explicitly prohibited.

### `AuditLogs`

Append-only security and administrative record.

| Column | Type | Rules |
|---|---|---|
| `AuditLogId` | `BIGINT IDENTITY` | PK |
| `OccurredAt` | `DATETIME2(3)` | Required |
| `CorrelationId` | `UNIQUEIDENTIFIER` | Required |
| `ActorUserId` | `INT` | Nullable FK to `Users` for system/unknown actors |
| `ActorObjectId` | `UNIQUEIDENTIFIER` | Nullable immutable identity snapshot |
| `ActorDisplay` | `NVARCHAR(320)` | Nullable snapshot |
| `Action` | `NVARCHAR(100)` | Required controlled action name |
| `TargetType` | `NVARCHAR(100)` | Nullable |
| `TargetId` | `NVARCHAR(200)` | Nullable |
| `Result` | `NVARCHAR(20)` | `Succeeded`, `Denied`, `Failed` |
| `Reason` | `NVARCHAR(1000)` | Nullable sanitized reason |
| `ClientIp` | `VARCHAR(45)` | Nullable, trusted proxy-derived |
| `UserAgent` | `NVARCHAR(500)` | Nullable, bounded |
| `BeforeJson` | `NVARCHAR(MAX)` | Nullable redacted snapshot/diff |
| `AfterJson` | `NVARCHAR(MAX)` | Nullable redacted snapshot/diff |
| `MetadataJson` | `NVARCHAR(MAX)` | Nullable schema-controlled metadata |

Constraints/indexes:

- Index `(OccurredAt DESC)` for retention/time searches.
- Index `(ActorUserId, OccurredAt DESC)`.
- Index `(TargetType, TargetId, OccurredAt DESC)`.
- Index `(Action, Result, OccurredAt DESC)`.
- Application roles receive insert/read as appropriate but no update/delete. Retention purge runs under a separately controlled maintenance role and is itself logged externally.

## 8. Status transition rules

| Entity | Allowed progression |
|---|---|
| `CollectionRuns` | `Running` -> `Succeeded` / `Partial` / `Failed` / `TimedOut` |
| `SourceItems` | `New` -> `Normalized` / `Duplicate` / `Rejected` / `Failed`; replay may reprocess failed/rejected under policy |
| `AIAnalyses` | `Pending` / `Retry` -> `InProgress` -> `Succeeded` / `Retry` / `Failed`; any not-started work may become `Cancelled` |
| `Alerts` | `Pending` -> `Ready` / `Suppressed`; `Ready` -> `Sent` / `Partial` / `Failed` based on deliveries |
| `AlertDeliveries` | `Pending` / `Retry` -> `InProgress` -> `Sent` / `Retry` / `Failed`; pending/retry may become `Cancelled` |
| `Users` | `Active` <-> `Disabled`, always audited |

Only atomic repository/service methods perform transitions. They verify current status, lease owner/expiry, and row version where applicable. Terminal historical states are not reset; retry/resend either transitions from a retryable state or creates a new linked record.

## 9. Key relationship and lifecycle rules

1. A `Vendor` may classify many `Threats`, `VendorMappings`, and `OrganizationAssets`. Disabling a vendor does not delete those rows.
2. A `Source` has many `CollectionRuns` and `SourceItems`. Disabling it stops future work but retains history.
3. A `CollectionRun` owns retrieval context for many `SourceItems`; a source item is never orphaned from its run.
4. `Threats` and `SourceItems` are many-to-many through `ThreatSources`, preserving multi-source evidence and supporting merges.
5. A `Threat` has zero or many `ThreatCVEs`, analyses, and alerts. Deleting/suppressing a threat must not silently erase sent alert or audit history.
6. `AlertRules` create `Alerts`; each alert creates recipient-specific `AlertDeliveries`. Recipient/rule deactivation affects future work only.
7. `Users` and `Roles` are many-to-many. `AuditLogs` preserve actor snapshots even if a user is later disabled.
8. Secrets are not modeled as database entities. Settings may reference an external secret name/identifier, never its value.

## 10. Duplicate and uniqueness guarantees

| Level | Primary guarantee | Fallback |
|---|---|---|
| Source observation | Unique source + external ID/version | Unique source + content hash; canonical URL hash assists investigation |
| Canonical threat | Filtered unique `CanonicalKey` | Transaction catches unique race and links existing threat |
| Threat/CVE | Unique threat + CVE | Primary CVE filtered uniqueness |
| Provenance | Unique threat + source item | Repeated confirmation updates `LastConfirmedAt` |
| AI work | Unique threat/type/provider/model/prompt/input hash | Explicit Admin-created new version only when inputs/config differ |
| Logical alert | Unique dedupe key from rule/version + threat/version | Suppressed row records why no delivery occurred |
| Initial delivery | Unique alert + recipient + sequence 1 | Resends increment sequence and link to prior delivery |
| Entra identity | Unique tenant + object ID | UPN/email are searchable but never identity keys |

Application prechecks improve error messages, but database unique constraints are the concurrency authority. Duplicate conflicts must be handled as an expected resolution path rather than exposed as server errors.

## 11. Migration and retention notes

1. Back up and restore-test the current database before establishing a migration baseline.
2. Inventory exact deployed types, constraints, indexes, collation, nullability, and data quality; this document does not override that evidence.
3. Introduce a versioned migration tool and mark the verified current schema as baseline. Never use `db.create_all()` for production evolution.
4. Create new tables first, then nullable additive columns, then backfill canonical data in bounded batches, then add filtered uniqueness only after duplicate review.
5. Validate every migration on a restored production-like copy and run existing Vendor/Threat CRUD/dashboard regressions.
6. Approve retention separately for raw source payloads, collection runs, AI versions, delivery bodies/metadata, diagnostic logs, and audit logs. Prefer pruning large payload bodies while retaining hashes and provenance identifiers.
7. SQL Server Express capacity must be monitored. Payload JSON and verbose history are the fastest growth areas; consider compressed/off-database archival only after security, backup, and retrieval implications are approved.
8. Foreign keys and retention procedures must preserve legal/security audit requirements and allow a full explanation of why a threat, analysis, or email was created.
