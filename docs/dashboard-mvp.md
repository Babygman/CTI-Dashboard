# Dashboard MVP

## Scope

Sprint 6C extends the existing dashboard without changing its route, database
schema, collector behavior, authentication, or overall Bootstrap/Chart.js layout.
The dashboard demonstrates the consolidation of CISA KEV and NVD intelligence.

## Dashboard metrics

The root route (`/`) displays:

- total, Critical, High, and KEV threat counts;
- total SourceItem count;
- CISA KEV and NVD SourceItem counts;
- threats linked to more than one distinct source;
- enabled source count;
- the latest CollectionRun source, status, timestamps, fetched, created,
  updated, skipped, and error counts;
- severity distribution; and
- the top 10 vendors by threat count.

The original Last Update metric remains available for backward compatibility.

## Query design

The route issues seven read-only SQL statements:

1. One aggregate over `Threats` for all threat cards and Last Update.
2. One aggregate over `SourceItems` joined to `Sources` for total, CISA,
   and NVD SourceItem counts.
3. One grouped subquery that counts threats with more than one distinct source.
4. One aggregate for enabled sources.
5. One `TOP 1` query for the latest collection run and source name.
6. One grouped aggregate for severity distribution.
7. One grouped `TOP 10` aggregate for vendors.

No query materializes all Threat or SourceItem rows. The latest run joins its
source in the same statement, so the route does not perform an N+1 lookup.

A collection run has an `ErrorMessage` field but no persisted numeric error
count. The dashboard reports the number of non-empty error-message lines, which
matches the collector service's newline-separated persistence format.

## Verification snapshot

Read-only verification was performed against the configured SQL Server on
2026-07-18.

| Check | Result |
| --- | --- |
| Dashboard HTTP status | 200 |
| Dashboard SQL statements | 7, all `SELECT` |
| End-to-end test-client request | 609.07 ms |
| Cumulative cursor execution | 228.56 ms |
| Total threats | 7,092 |
| Critical threats | 2,224 |
| High threats | 2,744 |
| KEV threats | 1,647 |
| Total SourceItems | 7,115 |
| CISA KEV SourceItems | 1,647 |
| NVD SourceItems | 5,468 |
| Multi-source threats | 23 |
| Enabled sources | 0 |

The latest run at verification time was an NVD `Success`: 5,468 fetched,
5,445 created, 23 updated, 0 skipped, and 0 errors.

Performance depends on SQL Server load, network latency, and data volume; this
snapshot is a point-in-time local measurement rather than a service-level
guarantee.

## Manual test procedure

1. Activate the project virtual environment and ensure `.env` contains the
   SQL Server SQLAlchemy connection URI.
2. Start Flask using the project's normal command.
3. Open `/` and confirm all ten metric cards, the latest collection-run table,
   severity chart, and top-10 vendor chart render.
4. Compare the cards with read-only SQL queries:

   ```sql
   SELECT
       COUNT(*) AS TotalThreats,
       SUM(CASE WHEN LOWER(Severity) = 'critical' THEN 1 ELSE 0 END) AS Critical,
       SUM(CASE WHEN LOWER(Severity) = 'high' THEN 1 ELSE 0 END) AS High,
       SUM(CASE WHEN KEV = 1 THEN 1 ELSE 0 END) AS KEV
   FROM dbo.Threats;

   SELECT
       COUNT(*) AS TotalSourceItems,
       SUM(CASE WHEN LOWER(s.SourceName) = 'cisa kev' THEN 1 ELSE 0 END) AS CISA,
       SUM(CASE WHEN LOWER(s.SourceName) = 'nvd' THEN 1 ELSE 0 END) AS NVD
   FROM dbo.SourceItems AS si
   INNER JOIN dbo.Sources AS s ON s.SourceId = si.SourceId;

   SELECT COUNT(*) AS MultiSourceThreats
   FROM (
       SELECT ThreatId
       FROM dbo.SourceItems
       WHERE ThreatId IS NOT NULL
       GROUP BY ThreatId
       HAVING COUNT(DISTINCT SourceId) > 1
   ) AS multi_source;

   SELECT COUNT(*) AS EnabledSources
   FROM dbo.Sources
   WHERE Enabled = 1;

   SELECT TOP (1)
       s.SourceName,
       cr.Status,
       cr.StartedAt,
       cr.FinishedAt,
       cr.ItemsFetched,
       cr.ItemsCreated,
       cr.ItemsUpdated,
       cr.ItemsSkipped,
       cr.ErrorMessage
   FROM dbo.CollectionRuns AS cr
   INNER JOIN dbo.Sources AS s ON s.SourceId = cr.SourceId
   ORDER BY cr.StartedAt DESC, cr.CollectionRunId DESC;
   ```

5. Run Python syntax parsing and compile `dashboard.html` through the Flask
   Jinja environment before release.

## Known limitations

- Error count is derived from newline-separated `ErrorMessage`; the schema
  does not store an explicit error count.
- Source-specific cards recognize the canonical names `CISA KEV` and `NVD`
  case-insensitively.
- Metrics are calculated on every request; caching is intentionally outside this
  sprint.
- Enabled Sources can legitimately be zero when source records exist but are
  disabled.
- Timestamps are displayed as stored by SQL Server; no user-time-zone conversion
  is applied.
