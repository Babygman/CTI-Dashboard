# Collector Framework

This document describes the Sprint 4 threat-source and collector foundation.
The framework currently performs no live network collection. Its only
executable collector uses local, clearly labelled demonstration data.

## Purpose and boundaries

The collector pipeline provides one contract for future CISA KEV, RSS, NVD,
Microsoft, Fortinet, Cisco, Veeam, and Broadcom collectors. It separates
provider retrieval and parsing from shared normalization, duplicate detection,
database persistence, run accounting, and logging.

Sprint 4 does not provide a scheduler, background service, live feed adapter,
AI analysis, email alerts, authentication, settings UI, or dashboard changes.
Commands are run manually through the existing Flask application factory.

## Components

- app/collectors/base.py defines the collector contract and fetch/parse errors.
- app/collectors/registry.py maps source types to collector classes.
- app/collectors/normalizer.py defines NormalizedItem and common validation.
- app/collectors/deduplication.py builds stable hashes and resolves duplicates.
- app/collectors/service.py owns persistence, item transaction boundaries,
  CollectionRun accounting, and structured log events.
- app/collectors/demo.py provides local test data and makes no HTTP calls.
- app/collectors/commands.py exposes the collector Flask CLI group.
- app/models/source.py stores source configuration and latest state.
- app/models/collection_run.py stores each execution summary.
- app/models/source_item.py stores source evidence and its linked Threat.

## Collector lifecycle

1. A CLI command resolves a configured Source and constructs its collector
   using the Source timeout.
2. The service inserts and commits a CollectionRun with status Running.
3. The collector fetch method obtains a provider payload. Future network
   collectors must apply timeout_seconds to every request.
4. The parse method yields raw item mappings. A provider adapter owns only
   provider-specific parsing.
5. Each raw item is normalized independently to NormalizedItem.
6. The service calculates a SHA-256 content hash and checks external identity,
   content identity, CVE, and title.
7. A unique item creates or updates a Threat and a Processed SourceItem.
   A duplicate SourceItem links to the existing Threat and is marked Duplicate.
8. Each item is committed separately. On item failure the transaction is
   rolled back, a Failed SourceItem is attempted, and remaining items continue.
9. The service finalizes counters, FinishedAt, Source status, and CollectionRun
   status, then writes a structured completion log.

Fetch or parse failure stops that run because there are no safe raw items to
process. An individual normalization or database error does not stop the run.

## Base collector contract

A collector subclasses BaseCollector and declares:

- source_name: stable display/configuration identity.
- source_type: stable registry key.
- fetch(): returns provider payload and handles transport/provider failures.
- parse(payload): yields raw mapping objects. The default supports a list.
- normalize(item): returns a NormalizedItem. The default uses shared rules.
- timeout_seconds: positive runtime value supplied to the constructor.

Future HTTP collectors must use bounded connection/read timeouts, map
transport/provider errors to CollectorError, limit response sizes, and avoid
writing database records directly. The collection service owns persistence.

Minimal outline:

    @collector_registry.register
    class ExampleCollector(BaseCollector):
        source_name = "Example Advisory Source"
        source_type = "Example"

        def fetch(self):
            # Apply self.timeout_seconds to the HTTP client.
            return provider_payload

        def parse(self, payload):
            for record in payload["items"]:
                yield {
                    "external_id": record["id"],
                    "title": record["title"],
                }

Override normalize only when a provider requires mapping before the common
normalizer. The returned structure must still satisfy NormalizedItem.

## Normalized item format

| Field | Type | Notes |
|---|---|---|
| external_id | string or null | Provider-stable item identity, maximum 500 |
| title | string | Required, maximum 255 for Threat compatibility |
| source_url | string or null | Reference URL, maximum 1000 |
| published_date | datetime or null | Converted to timezone-naive UTC |
| source_name | string | Collector identity, maximum 100 |
| vendor_name | string or null | Existing vendor match or new normalized vendor |
| severity | string or null | Critical, High, Medium, or Low |
| cve_ids | tuple of strings | Uppercase validated CVE identifiers |
| cvss | decimal or null | Rounded to one decimal, range 0.0 through 10.0 |
| kev | boolean | Exploited-vulnerability indicator |
| summary | string or null | Source summary |
| raw_content | string | Serialized evidence used for diagnosis |

The current Threat table has one CVE field, so Sprint 4 writes the first
normalized CVE to Threat.CVE. The normalized structure already supports more
than one CVE for future ThreatCVEs work.

## Duplicate detection

Duplicate checks are ordered:

1. SourceId plus ExternalId finds a previously observed provider record. A
   filtered unique SQL Server index is the concurrency guard when ExternalId
   exists.
2. A SHA-256 hash of normalized canonical fields identifies exact equivalent
   content, even when an external identifier differs.
3. The first normalized CVE resolves an existing Threat when content came from
   a different representation.
4. A case-insensitive exact title check is the final fallback only when an
   item has no CVE. Distinct CVEs are never merged on title alone.

The content hash excludes external_id and source_name so the same canonical
advisory can be recognized across identifiers and future sources. It includes
title, URL, publication date, vendor, severity, CVEs, CVSS, KEV, and summary.

When the same external identifier arrives with changed content, its SourceItem
and linked Threat are updated and the run increments ItemsUpdated. An exact
repeat increments ItemsSkipped. A different external identifier with duplicate
content creates a Duplicate SourceItem linked to the existing Threat, preserving
evidence without creating another Threat. A CVE/title identity match with different
content updates and links the existing Threat instead of inserting a duplicate.

This is an exact foundation, not final fuzzy/canonical advisory merging.
Multi-CVE and conflicting cross-source precedence remain future work.

## CollectionRun lifecycle

Allowed values:

- Running: inserted before fetch begins.
- Success: fetch and every item completed without an error.
- Partial: at least one item succeeded or was skipped and at least one failed.
- Failed: fetch/parse failed, or every fetched item failed.

Counters:

- ItemsFetched is the parsed raw item count.
- ItemsCreated is the number of new Threat records.
- ItemsUpdated is the number of changed known external records.
- ItemsSkipped is the number of duplicate observations.

ErrorMessage contains a bounded run summary suitable for operator diagnosis.
Detailed tracebacks remain in protected application logs. A successful run
updates Source.LastSuccessfulCollection; every final state updates
Source.LastCollectionStatus.

## SourceItem lifecycle

Allowed values:

- Pending: database default before processing.
- Processed: unique source evidence linked to a Threat.
- Duplicate: evidence or a repeat that resolves to an existing Threat.
- Failed: raw item could not be normalized or persisted.

FirstSeenAt records initial evidence creation. LastSeenAt changes when the same
external observation is encountered again. ThreatId remains nullable for failed
items and points to Threats when resolution succeeds.

The per-item commit design ensures rollback of a failed item does not remove
earlier successful items or the CollectionRun. If recording the Failed
SourceItem itself fails, that secondary failure is logged and the run still
continues.

## Adding a collector

1. Confirm the provider offers an approved, supported API or feed and document
   its terms, cadence, authentication, and retention.
2. Add one adapter module under app/collectors.
3. Subclass BaseCollector and register the class with collector_registry.
4. Implement fetch with explicit timeout, response-size, HTTP status, retry,
   redirect, URL, and content-type handling appropriate to the provider.
5. Implement parse to yield one mapping per provider item.
6. Use the shared normalizer, or override normalize only for provider mapping.
7. Add the Source row disabled first. Never store credentials in Source.
8. Add sanitized fixtures for success, empty response, malformed data,
   timeout, provider error, update, and duplicate cases.
9. Run the adapter through run_collector; do not perform database writes in
   fetch, parse, or normalize.
10. Enable the source only after idempotency, provenance, and failure behavior
    have been reviewed.

Import the module from app/collectors/__init__.py or from an explicit
registration loader so registration occurs before registry lookup.

## CLI usage

The commands use the application factory and configured SQL Server connection:

    flask --app app:create_app collector seed-sources
    flask --app app:create_app collector run-demo
    flask --app app:create_app collector status

seed-sources inserts disabled placeholders for CISA KEV, NVD, Microsoft,
Fortinet, Cisco, Veeam, and Broadcom VMware. It is idempotent by case-insensitive
SourceName lookup and the database unique constraint.

run-demo inserts a disabled Local Demonstration Collector source if necessary,
then processes three local items: two unique threats and one duplicate. Output
includes run ID, final status, fetched, created, updated, skipped, and errors.
Re-running the command does not create additional Threats for unchanged items.

status lists every configured source, enablement, latest status, and latest
start time. It does not initiate collection.

Before using these commands, apply the guarded Sources, CollectionRuns, and
SourceItems blocks from database/init.sql to the target database through the
project's reviewed database-change process.

## Structured logging

The service emits JSON messages through the Flask/Python logger for:

- collection_started
- collection_item_failed
- collection_failed_item_record_error
- collection_failed
- collection_finished

Fields include UTC timestamp, run/source IDs, source or worker identity,
status, counters, item number, and sanitized error details. The current
application formatter may prefix the JSON message; production JSON formatting,
rotation, forwarding, and secret-redaction policy belong to deployment work.

## Known limitations

- There are no live collectors or outbound HTTP requests.
- There is no scheduler, continuous worker, lease, concurrency lock, or retry
  delay. Commands are manual and concurrent runs must be operationally avoided.
- Source configuration has no provider cursor, ETag, or conditional-request
  fields in the Sprint 4 schema.
- Threat supports one displayed CVE; all normalized CVEs are not yet persisted.
- Exact hashes, CVE, and titles do not solve fuzzy duplicates or conflicting
  source precedence.
- Automatic creation of an unknown Vendor is suitable for the demo foundation
  but requires mapping/approval policy before live collectors are enabled.
- The demo command intentionally creates clearly labelled demo Vendors,
  SourceItems, and Threats in the configured database. Use a test database when
  production data must remain clean.
- Item rollback is isolated, but SQL Server deadlock/transient retry and
  database-backed worker leases are future reliability work.
- RawContent retention, payload size limits, audit UI, source management UI,
  and database migration tooling remain future sprints.
