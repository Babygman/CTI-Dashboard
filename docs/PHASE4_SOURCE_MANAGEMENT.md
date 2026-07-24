# Phase 4 Sprint 1: News Search and Source Management

## News search and filters

The existing News feed continues to combine manual `NewsItems` and collected
canonical `Threats`. Search, filtering, count, sorting, and pagination are
performed by SQL before the current page is loaded.

Available controls:

- Search across title, summary, vendor, product, CVE, and source.
- Source.
- Severity.
- Recommendation.
- Relevance through the existing All, Relevant, and Not Relevant tabs.
- Inclusive published-date range.
- Page sizes of 25, 50, and 100.
- Reset.

Active values are retained when changing relevance tabs, page, or page size.
The established ordering remains published date descending, followed by
record type and record ID.

For collected threats, product evidence is searched in the normalized source
metadata retained by the Phase 3 ingestion pipeline. CVE search covers both
the legacy primary CVE column and normalized multi-CVE relationships.

## Threat Sources administration

The Administration menu now labels the existing source administration area
as **Threat Sources**. It displays every configured `Sources` record,
including sources whose collector is not yet implemented.

The list reports:

- source name and enabled state;
- registered collector type and collection interval;
- latest run, latest successful collection, status, health, and duration;
- persisted SourceItem count;
- cumulative new canonical threats;
- run-error count and most recent error;
- latest imported, updated, and skipped counters.

Administrators can enable, disable, run, or open the detail page for each
source. These actions reuse the existing source routes, collection lease, and
collector runner. No source-editing function was added.

## Collector history

Execution history remains persisted in `CollectionRuns`. Each run records:

- start and finish timestamps;
- Running, Success, Partial, or Failed status;
- fetched, created, updated, and skipped counts;
- worker identity;
- error details.

Last duration is derived from the persisted start and finish timestamps.
No database migration is required for Sprint 1.

## Verification

```shell
pytest
ruff check .
python scripts/check_templates.py
```

Regression coverage includes mixed manual/collected News search, all filter
types, page-size and pagination retention, source status metrics, and
administrator actions.
