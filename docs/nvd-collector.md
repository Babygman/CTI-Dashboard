# NVD Collector

## Scope

The NVD collector imports the official NVD CVE JSON 2.0 **modified feed** into the existing collector framework. It enriches canonical Threat records by CVE and creates source evidence without changing the dashboard or UI.

This collector does not perform a complete historical NVD bootstrap. The modified feed contains CVEs published or modified during the previous eight days. Historical year-feed ingestion, META-based download suppression, API-key support, and scheduling are outside Sprint 6B.

## Official sources

- Feed: `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz`
- Feed metadata: `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.meta`
- JSON 2.0 schema: `https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema`
- Feed documentation: `https://nvd.nist.gov/vuln/data-feeds`

NVD documents the recent and modified feeds as updating approximately every two hours. Production scheduling should consult the META file in a future sprint so unchanged feed files are not downloaded repeatedly.

## Registration and CLI

The collector registers as:

- Source name: `NVD`
- Source type: `Nvd`
- CLI name: `nvd`

Run it with:

```powershell
flask collector seed-sources
flask collector run nvd
flask collector status
```

The CLI uses `Sources.FeedUrl` when configured and otherwise falls back to the official modified-feed URL. Existing NVD Source rows with a null FeedUrl therefore remain runnable.

Expected output follows the shared collector format:

```text
run_id: 2
status: Success
fetched: 1250
created: 900
updated: 300
skipped: 50
errors: 0
duration_seconds: 42.123
```

Counts vary whenever NVD updates the feed.

## Download reliability

The collector:

- downloads the compressed GZip feed over HTTPS;
- uses the Source timeout;
- retries once after transport, decompression, encoding, or JSON errors;
- rejects compressed payloads larger than 50 MiB;
- rejects decompressed payloads larger than 250 MiB;
- validates the top-level `vulnerabilities` collection; and
- skips NVD records whose `vulnStatus` is `Rejected`.

A download or feed-level parse failure completes the CollectionRun as Failed. Item-level normalization or persistence failures are isolated and can produce Partial status.

## Normalization

| NVD JSON field | Normalized field | Persistence |
|---|---|---|
| `cve.id` | external_id, cve_ids | SourceItems.ExternalId, SourceItems.CVE, Threats.CVE |
| English `cve.descriptions` value | title and summary | SourceItems.Title, Threats.Title/Summary under precedence |
| generated NVD detail URL | source_url | SourceItems.SourceUrl; Threats.ReferenceUrl when NVD owns the display fields |
| `cve.published` | published_date | SourceItems.PublishedDate and canonical earliest publication date |
| `cve.lastModified` | source_modified_date | SourceItems.SourceModifiedDate and Threats.ModifiedDate |
| newest usable CVSS metric | cvss and severity | Threats.CVSS/Severity under precedence |
| `cve.affected` or configuration CPEs | vendor/product candidates | unambiguous Vendor plus NormalizedMetadata |
| references, weaknesses, CVSS vector/source/version, status, CISA mirror fields | normalized_metadata | SourceItems.NormalizedMetadata JSON |
| complete CVE object | raw_content | SourceItems.RawContent |

The title is `CVE-ID: description`, bounded to 255 characters. The complete English description remains in Summary and raw evidence.

### CVSS selection

The collector evaluates versions in this order:

1. CVSS 4.0
2. CVSS 3.1
3. CVSS 3.0
4. CVSS 2.0

Within one version it prefers a metric from the CVE source identifier, then a metric marked Primary, then other metrics. The selected score, severity, vector, version, source, and type are retained in NormalizedMetadata. The collector does not select the maximum score.

NVD fields that mirror CISA KEV are retained in NormalizedMetadata but do not set the canonical KEV flag. CISA evidence remains authoritative for KEV membership.

## Matching and duplicate handling

Processing order is:

1. `(SourceId, ExternalId)` finds an existing NVD SourceItem.
2. An unchanged ContentHash updates the observation/run link and is counted as skipped.
3. Exact cross-source ContentHash may link duplicate evidence.
4. Exact uppercase CVE matches one existing Threat.
5. A missing CVE match creates a new Threat.

If more than one Threat has the same case-insensitive CVE, the item fails as ambiguous rather than silently selecting one row.

MatchMethod values used by the shared service are:

- `ExistingLink`
- `ContentHash`
- `CVE`
- `Title` for legacy CVE-less collectors
- `Created`
- `Failed`

Each successful NVD SourceItem records CollectionRunId, CVE, SourceModifiedDate, NormalizedMetadata, and MatchMethod. Reprocessing an existing SourceItem changes CollectionRunId to the most recent run that observed it because SourceItems remain mutable current observations in the existing schema.

## Field precedence

When NVD matches a CISA Threat:

- CISA keeps the canonical Title, Vendor, Source, ReferenceUrl, Recommendation, and KEV assertion.
- NVD supplies CVSS and its derived Severity when a usable metric exists.
- NVD supplies the canonical Summary.
- PublishedDate becomes the earlier credible publication date; CISA `dateAdded` is not treated as the original publication date.
- ModifiedDate becomes the latest provider modification date.
- Missing NVD values do not erase populated canonical values.

When NVD creates a Threat, its normalized values populate the canonical record. A later CISA match can take ownership of CISA-authoritative display and KEV fields while retaining NVD CVSS/Summary enrichment.

## CollectionRun and SourceItem lifecycle

Every invocation creates one CollectionRun before download. Each processed, duplicate, or failed SourceItem receives that run ID. At completion, the run records fetched, created, updated, skipped, error count/message, timing, worker, and final Success/Partial/Failed status through the existing framework.

For an existing CISA CVE, NVD creates an additional SourceItem with the same ThreatId. It does not create a second Threat. For a new CVE, both the Threat and NVD SourceItem are created in the same item transaction.

## Manual test procedure

1. Back up the SQL Server database.
2. Confirm Sprint 6A SQL has been applied.
3. Confirm the NVD source exists:

   ```sql
   SELECT SourceId, SourceName, SourceType, FeedUrl, Enabled, TimeoutSeconds
   FROM dbo.Sources
   WHERE SourceName = N'NVD';
   ```

4. Record baseline counts:

   ```sql
   SELECT COUNT(*) AS ThreatCount FROM dbo.Threats;
   SELECT COUNT(*) AS SourceItemCount FROM dbo.SourceItems;
   SELECT COUNT(*) AS RunCount FROM dbo.CollectionRuns;
   ```

5. Run `flask collector run nvd` from the project virtual environment.
6. Confirm the command reports Success or Partial with item-level errors explained.
7. Verify provenance:

   ```sql
   SELECT TOP (20)
       si.SourceItemId,
       si.CollectionRunId,
       si.CVE,
       si.ThreatId,
       si.SourceModifiedDate,
       si.MatchMethod,
       si.SourceUrl
   FROM dbo.SourceItems AS si
   INNER JOIN dbo.Sources AS s ON s.SourceId = si.SourceId
   WHERE s.SourceName = N'NVD'
   ORDER BY si.SourceItemId DESC;
   ```

8. Verify cross-source consolidation:

   ```sql
   SELECT
       t.CVE,
       t.ThreatId,
       COUNT(DISTINCT si.SourceId) AS SourceCount
   FROM dbo.Threats AS t
   INNER JOIN dbo.SourceItems AS si ON si.ThreatId = t.ThreatId
   WHERE t.CVE IS NOT NULL
   GROUP BY t.CVE, t.ThreatId
   HAVING COUNT(DISTINCT si.SourceId) > 1;
   ```

9. Run the collector again. Unchanged NVD items should be skipped, Threat and NVD SourceItem counts should remain stable, and a new CollectionRun should be recorded.

## Expected database changes per run

- One new CollectionRuns row.
- One NVD SourceItem for each newly observed NVD CVE in the modified feed.
- Existing NVD SourceItems updated in place when NVD content changes or is confirmed.
- Existing CISA Threat rows enriched in place when CVEs match.
- New Threat rows only for CVEs not already present.
- New Vendor rows only when a new/NVD-owned Threat has exactly one unambiguous vendor candidate.
- No changes to database schema.

## Limitations

- The modified feed is incremental and is not a full historical NVD import.
- META-file conditional download is not implemented.
- No scheduler or distributed run lock is included.
- SourceItems retain only their latest CollectionRunId, not a per-run observation history.
- A CVE maps to one canonical Threat; multi-CVE advisory modeling remains deferred.
- Ambiguous vendor candidates remain only in NormalizedMetadata and do not create a Vendor.
- CPE parsing is intentionally conservative and may leave VendorId empty.
- NVD CISA mirror fields do not substitute for direct CISA collector evidence.
