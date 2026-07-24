# CTI Dashboard Release Verification

- Version: `v2.0.0-rc1`
- Commit: `c25c0618e073c08990f5228928dd835cb79324d9` plus this release-verification record
- Database Version: `20260724_00 (head)` on the configured production SQL Server
- Test Result: `190 passed, 3 skipped, 300 warnings, 55 subtests passed`
- Ready for Production: **YES**

## Verification Result

| Item | Result | Notes |
| --- | --- | --- |
| Production SQL Server | PASS | Connection succeeded and Alembic reported `20260724_00 (head)`. |
| Organization Settings | PASS WITH CONDITIONS | `CompanyName`, `CompanyShortName`, and `Department` loaded from SQL Server. `SCT` and `IT Department` prove database values take precedence over the different config defaults. |
| Dashboard | PASS | Production-backed dashboard loaded successfully. |
| Assets | PASS | Production asset `FG200E` loaded successfully. |
| News | PASS | Page loaded successfully; production currently contains no news items. |
| Relevant Threats | PASS | 7,092 production rows; definitive clean-process measurement was 4.971 seconds cold and 0.317 seconds warm. Pagination rendered exactly 25, 50, and 100 records while preserving the 323-record relevant total. |
| Awareness | PASS WITH CONDITIONS | Awareness list and generation/edit screen loaded successfully. Production currently contains no saved awareness records. |
| PDF | PASS | Valid one-page A4 PDF generated and visually inspected. SQL Server organization name, short name, and department were rendered. |
| PNG | PASS | Valid `1240 x 1754` PNG generated and visually inspected. SQL Server organization name and department were rendered. |
| Placeholder text | PASS | The discovered `CVSS: None` export defect was fixed and regression-tested. Final PDF renders `ไม่ระบุ`. |
| Config fallback precedence | PASS | Populated SQL Server values were used instead of config fallbacks. Fallbacks were used only for missing or blank database settings. |

## Known Issues

1. Production Organization Settings has no active `HeaderText` or `FooterText` records, and `CompanyLogo` is blank. Config fallback is therefore expected for header/footer, and no logo is rendered.
2. Opening `/awareness/create/threat/<id>` with GET immediately persists a Draft record before the user saves. The verification record created during release testing was identified and removed.
3. Source-provided recommendation text can remain in English in the PDF when the production threat recommendation itself is English.
4. The test suite reports 240 existing deprecation warnings, primarily for `datetime.utcnow()`.

## PP1 Performance Verification

Production dataset:

- Total threats: 7,092
- Active assets: 1
- Relevant records: 323
- Default rendered page: 25 records
- Response size: 26,553 bytes

Baseline profile:

| Stage | Time |
| --- | ---: |
| Asset SQL | 678 ms |
| Asset ORM | 20 ms |
| Threat SQL | 150 ms |
| Threat ORM | 1,538 ms |
| Asset matching and recommendation | 308 ms |
| Template rendering, including N+1 CVE loads | 27,351 ms |
| Total | 30,045 ms |

Optimized cold profile:

| Stage | Time |
| --- | ---: |
| Asset SQL | 648 ms |
| Asset ORM | 21 ms |
| Filtered count SQL and result | 3,917 ms |
| 25-row page SQL | 96 ms |
| Page ORM materialization | 214 ms |
| Asset matching and recommendation | 5 ms |
| Template rendering | 22 ms |

Final release-verification HTTP measurements:

- Cold request: 4.971 seconds (target: under 5 seconds)
- Warm request: 0.317 seconds (target: under 2 seconds)
- Page-size verification: 25, 50, and 100 rows rendered with the correct total of 323.
- Filter verification: Need Awareness returned 284 total records and Need Patch returned 30, matching the previously verified SQL filter totals.
- SQL filter totals matched the original Python business logic for all eight filters.
- SQL Server denied `SHOWPLAN` permission. Existing index metadata was reviewed; no index was added because the remaining cold filter uses leading-wildcard searches over text/LOB columns, which a conventional nonclustered index cannot accelerate.

## Release Decision

All required production, migration, functional, performance, pagination, branding, export, and visual checks passed. The final automated gates were `188 passed, 3 skipped`, Ruff clean, and 35 templates compiled successfully.

PP1 removes the Relevant Threats release blocker and meets both performance targets. The release candidate is ready for production.

## News and Relevant Threats Priority Fix

### News root cause

The automated CISA and NVD collectors persist canonical cybersecurity records in the `Threats` table. The News route queried only `NewsItems`, a separate table populated by the manual Add News workflow. Production contained 7,092 collected threats and no manual News records, so All Threats was populated while News correctly returned an empty `NewsItems` result.

### Fix summary

- News now presents one paginated feed containing manual `NewsItems` and collected `Threats`.
- All, Relevant, and Not Relevant tabs remain available and filter both record types.
- Collected records link to Threat details and the existing threat-based Awareness generator; manual records retain their News detail and Awareness workflows.
- SQL performs filtering, total count, ordering, and 25-row pagination. Existing matching and recommendation logic evaluates only the current page.
- The empty state now appears only when the active News view has no matching manual or collected records.
- Relevant Threats now supports SQL-backed search plus vendor, severity, recommendation, impact-status, and matched-asset filters.
- Search covers title, direct and normalized CVE, vendor, product terms present in threat text, source, summary, and recommendation text.
- Tabs, 25/50/100 page sizes, pagination, and active filter values are preserved in generated links.

### Production-sized verification

Dataset at verification time:

- Threats: 7,092
- Active assets: 2
- News All: 7,092 records; 25 rendered; 1.596 seconds
- News Relevant: 426 records; 25 rendered; 4.726 seconds cold

Relevant Threats filter samples:

| Filter | Total | Response time |
| --- | ---: | ---: |
| Search `Fortinet` | 41 | 1.846 seconds |
| Search `FortiGate` | 2 | 1.726 seconds |
| Severity `Critical` | 2,224 | 0.399 seconds |
| Recommendation `Need Patch` | 131 | 7.493 seconds cold / 3.176 seconds warm |
| Matched asset `FG200E` | 41 | 2.742 seconds |
| Fortinet + High + Need Patch + FG200E | 4 | 3.871 seconds |

Pagination links retained search, severity, recommendation, matched asset, selected tab, and 25/50/100 page size parameters. The existing tab predicates and deterministic asset-matching/recommendation functions were reused without changing business rules.

Final verification:

- Pytest: `190 passed, 3 skipped, 300 warnings, 55 subtests passed`
- Ruff: passed
- Template check: 35 templates compiled successfully

## Phase 4 Sprint 1: News Search and Source Management

### News

- Added SQL-backed search across title, summary, vendor, product, CVE, and
  source for the unified manual-and-collected News feed.
- Added source, severity, recommendation, relevance, and inclusive date-range
  filters.
- Added 25, 50, and 100 page sizes.
- Preserved the existing sorting, relevance tabs, record totals, detail
  links, and Awareness actions.
- Active search and filter values remain selected across tabs, pages, and
  page-size changes.

### Threat Sources

- Renamed the Administration menu entry and source list to Threat Sources.
- The list continues to include every configured source and now exposes
  collector, interval, latest run/success, status, persisted imports, new
  threats, and errors.
- Added inline Enable, Disable, and Run Now actions using the existing source
  routes and collection runner.
- Latest duration and imported, updated, skipped, and error details are
  derived from existing persisted `CollectionRuns` history.
- No schema migration or collector changes were required.

Detailed administrator and verification notes are available in
`docs/PHASE4_SOURCE_MANAGEMENT.md`.

Validation:

- Pytest: `198 passed, 3 skipped, 345 warnings, 55 subtests passed`
- Ruff: passed
- Template compilation: 35 templates passed
- Production SQL Server query smoke tests: passed for English and Japanese
  search, source/severity/recommendation/date filters, page size, and Threat
  Sources status rendering

## Phase 3 Threat Intelligence Source Framework

### Scope

- Retained the existing NVD and CISA KEV collectors.
- Added registered Microsoft Security Response Center and JPCERT/CC
  collectors using their official update and RSS endpoints.
- Centralized source definitions and feed defaults.
- Added generic construction of collectors from persisted `Sources` settings.
- Connected every registered source to the existing scheduler, normalization,
  canonical matching, deduplication, source-item, and threat-observation
  pipeline.
- Preserved the unified `Threat` model consumed by News, Relevant Threats,
  Asset Matching, and Awareness generation.

### Database migration

- New migration head: `20260724_01`
- Migration type: data-only; no schema changes
- Existing source and threat data is preserved.
- Newly configured JPCERT collection remains disabled until explicitly
  enabled by an administrator.
- Detailed deployment and rollback guidance:
  `docs/PHASE3_SOURCE_FRAMEWORK.md`

### Verification

- Provider normalization tests cover official MSRC JSON and JPCERT RSS 1.0
  payload shapes.
- Shared-pipeline tests cover deduplication, source attribution, scheduler
  discovery, and visibility on the existing News page.
- Fresh-database migration reached `20260724_01 (head)` successfully.
- Full pytest: `196 passed, 3 skipped, 312 warnings, 55 subtests passed`
- Ruff: passed
- Template check: 35 templates compiled successfully
