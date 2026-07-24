# Phase 3 Threat Intelligence Source Framework

## Overview

Phase 3 extends the existing collection pipeline with registered, pluggable
collectors for:

- NVD
- CISA Known Exploited Vulnerabilities
- Microsoft Security Response Center
- JPCERT/CC

Every collector implements the same `BaseCollector` contract:

1. `fetch()` retrieves the provider payload with the configured timeout.
2. `parse()` yields provider records.
3. `normalize()` produces the shared `NormalizedItem` representation.
4. `run_collector()` applies the existing canonical matching, deduplication,
   source evidence, CVE persistence, and threat-observation pipeline.

The originating source is retained on `SourceItems.SourceId` and
`ThreatObservations.SourceId`. Each source item also retains its provider
identifier, URL, normalized metadata, and original content.

## Source configuration

Source definitions and default feed URLs are centralized in
`app/collectors/source_config.py`. Runtime settings remain in the `Sources`
table:

- `SourceType` selects the registered collector.
- `FeedUrl` overrides the collector's default endpoint.
- `TimeoutSeconds` controls external request timeouts.
- `Enabled` controls scheduler eligibility.
- `CollectionIntervalMinutes` controls collection frequency.

New MSRC and JPCERT sources are disabled by default. Enable them from the
existing Source Administration page after confirming outbound connectivity.
The existing collection worker discovers enabled registered collectors
without provider-specific scheduler branches.

## Adding a future source

1. Add a `BaseCollector` subclass with a unique `source_type`.
2. Register it with `@collector_registry.register`.
3. Convert provider records to `NormalizedItem` in `normalize()`.
4. Import the module from `app/collectors/__init__.py`.
5. Add its source definition to `SOURCE_DEFINITIONS`.
6. Add provider payload and shared-pipeline regression tests.

No News, Relevant Threats, Asset Matching, or Awareness-specific code is
required. These features continue to consume the unified `Threat` model.

## Migration notes

New Alembic head: `20260724_01`

Apply:

```shell
flask db upgrade
```

The migration is data-only and preserves all existing threats, source items,
observations, and source run history. It:

- changes the existing Microsoft Security Response Center source type to
  `MicrosoftMsrc`;
- configures the official MSRC updates endpoint;
- inserts or updates the JPCERT source with its official RSS endpoint;
- leaves JPCERT disabled when it is newly inserted.

Downgrading to `20260724_00` restores the previous Microsoft source type and
clears the new feed configuration. JPCERT is retained but disabled so source
history is never deleted.

## Operational commands

```shell
flask collector seed-sources
flask collector run microsoft-msrc
flask collector run jpcert
flask collector status
```

The manual run commands use the same collector and persistence pipeline as
the scheduled worker.
