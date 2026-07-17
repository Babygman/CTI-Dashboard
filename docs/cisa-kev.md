# CISA KEV Production Collector

## Official source

The collector downloads the CISA Known Exploited Vulnerabilities catalog from
the official JSON feed:

    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Catalog page:

    https://www.cisa.gov/known-exploited-vulnerabilities-catalog

CISA describes this catalog as the authoritative source of vulnerabilities
known to have been exploited in the wild. No mirror, demo payload, NVD endpoint,
RSS feed, or third-party API is used by this collector.

## Collection flow

1. The operator runs the named CISA collector through the Flask CLI.
2. The command resolves the existing CISA KEV Source row and uses its
   TimeoutSeconds and optional FeedUrl.
3. CisaKevCollector.fetch downloads the official JSON document with an explicit
   user agent, JSON Accept header, and network timeout.
4. A failed request or invalid JSON response is retried once. A second failure
   raises CollectorError and the collection service finalizes the run as Failed.
5. parse validates the catalog envelope and yields the vulnerabilities array.
6. Each vulnerability is normalized and processed independently by the shared
   collector service.
7. The service stores SourceItem evidence, resolves duplicates, creates or
   updates Threat and Vendor records, commits each item separately, and updates
   CollectionRun and Source status.
8. Existing dashboard queries immediately include the committed Threat rows;
   no dashboard layout or route changes are required.

One malformed vulnerability creates a Failed SourceItem and does not stop later
items. The final CollectionRun is Partial when at least one item succeeds and at
least one fails.

## Normalization

The adapter maps the current CISA JSON fields as follows:

| CISA field | Normalized field | Threat storage |
|---|---|---|
| cveID | external_id, cve_ids | CVE |
| vendorProject | vendor_name | VendorId through Vendors |
| product | product | Included in Summary and RawContent |
| vulnerabilityName | title | Title |
| dateAdded | published_date | PublishedDate |
| shortDescription | summary | Summary |
| requiredAction | recommendation | Recommendation |
| dueDate | due_date | Included in Recommendation and RawContent |
| knownRansomwareCampaignUse | known_ransomware_campaign_use | Included in Summary and RawContent |
| notes | notes | Included in Summary and RawContent |
| generated catalog search URL | source_url | ReferenceUrl |
| complete vulnerability object | raw_content | SourceItems.RawContent |

Constant mappings:

- source_name and Threat.Source: CISA KEV
- severity and Threat.Severity: Critical
- kev and Threat.KEV: true
- cvss: null because the CISA KEV JSON catalog does not provide CVSS

The normalized structure has 17 fields: external ID, title, source URL,
published date, source name, vendor, product, severity, CVEs, CVSS, KEV,
summary, recommendation, ransomware-use status, due date, notes, and raw
content.

The title is bounded to the existing Threat Title length. The complete source
record remains in RawContent. Dates are parsed as UTC-compatible datetime
values. CVEs are uppercase and validated by the shared normalizer.

## Duplicate strategy

The collector uses the shared layered duplicate service:

1. SourceId plus cveID is the stable source identity. The filtered SQL Server
   unique index on SourceItems protects this identity from concurrent duplicate
   rows.
2. ContentHash is calculated from normalized advisory content, including the
   CISA-specific product, action, ransomware-use, due-date, and notes values.
3. CVE lookup resolves an existing Threat even if it originated from a manual
   entry or another future source.
4. Exact case-insensitive title lookup is used only for CVE-less items; distinct CVEs are never merged solely because CISA gives them the same name.

An unchanged repeated cveID is skipped and updates LastSeenAt. If CISA changes
the content for an existing cveID, the SourceItem and linked Threat are updated.
A different source item with equivalent canonical content is stored as
Duplicate and linked to the existing Threat.

## CLI usage

Ensure the guarded collection tables exist and seed sources once:

    flask --app app:create_app collector seed-sources

Run CISA KEV manually:

    flask --app app:create_app collector run cisa-kev

Inspect current source state:

    flask --app app:create_app collector status

The explicit run command is allowed for a disabled Source. Enabled is reserved
for future scheduler behavior; Sprint 5 does not add a scheduler.

If the CISA Source row has FeedUrl, the command uses it. Otherwise it falls
back to the official URL compiled into the collector. TimeoutSeconds controls
each HTTP attempt.

## Expected output

Exact counts depend on the catalog and existing database contents:

    run_id: 42
    status: Success
    fetched: 1647
    created: 1647
    updated: 0
    skipped: 0
    errors: 0
    duration_seconds: 12.345

On a repeat run with unchanged content, created and updated should be zero and
skipped should equal fetched. Existing manual Threats with matching CVEs are updated with the CISA fields
and linked through a Processed SourceItem rather than creating another Threat.

A terminal fetch/parse failure prints status Failed, the error count and
duration, updates CollectionRun and Source status, and exits with a nonzero
status. Partial item processing is printed as Partial and retains successfully
committed items.

## Reliability and logging

- Every request uses Source.TimeoutSeconds.
- One retry is attempted after request, HTTP, or JSON decoding failure.
- The shared service records Running then Success, Partial, or Failed.
- Source.LastCollectionStatus is always finalized.
- Source.LastSuccessfulCollection changes only after a fully successful run.
- Per-item transactions prevent one invalid item from rolling back earlier
  successful items.
- JSON log events cover collection start, retry, item failure, terminal failure,
  and completion with run/source IDs and counters.

## Operational limitations

- Collection is manual; no scheduler, lease, or overlapping-run protection is
  implemented.
- The initial import processes the complete catalog and commits each item,
  which favors recovery over maximum throughput.
- CISA supplies no CVSS value in this feed, so CVSS remains null.
- Product, ransomware-use, due date, and notes have no dedicated Threat columns;
  they are retained in the normalized hash, Summary/Recommendation, and raw
  SourceItem evidence.
- Unknown CISA vendors are created automatically. A reviewed vendor-alias
  mapping policy is still required before additional sources are introduced.
- The collector depends on CISA availability and the documented JSON field
  contract. Schema changes appear as Partial/Failed runs rather than silent
  data loss.
- Manual operators must avoid concurrent runs until database-backed run leasing
  or scheduler controls are implemented.
