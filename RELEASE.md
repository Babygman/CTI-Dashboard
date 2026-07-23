# CTI Dashboard Release Verification

- Version: `v2.0.0-rc1` (candidate; tag withheld)
- Commit: `PP1 - Optimize Relevant Threats performance`
- Database Version: `20260724_00 (head)` on the configured production SQL Server
- Test Result: `188 passed, 3 skipped, 240 warnings, 55 subtests passed`
- Ready for Production: **YES**

## Verification Result

| Item | Result | Notes |
| --- | --- | --- |
| Production SQL Server | PASS | Connection succeeded and Alembic reported `20260724_00 (head)`. |
| Organization Settings | PASS WITH CONDITIONS | `CompanyName`, `CompanyShortName`, and `Department` loaded from SQL Server. `SCT` and `IT Department` prove database values take precedence over the different config defaults. |
| Dashboard | PASS | Production-backed dashboard loaded successfully. |
| Assets | PASS | Production asset `FG200E` loaded successfully. |
| News | PASS | Page loaded successfully; production currently contains no news items. |
| Relevant Threats | PASS | 7,092 production rows; 4.884-second cold request and 0.319-second warm request. Only the selected 25/50/100-row page is loaded and rendered. |
| Awareness | PASS WITH CONDITIONS | Awareness list and generation/edit screen loaded successfully. Production currently contains no saved awareness records. |
| PDF | PASS | Valid one-page A4 PDF generated. SQL Server organization name, short name, and department were rendered. |
| PNG | PASS | Valid `1240 x 1754` PNG generated. SQL Server organization name and department were rendered. |
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

Final HTTP measurements:

- Cold request: 4.884 seconds (target: under 5 seconds)
- Warm request: 0.319 seconds (target: under 2 seconds)
- SQL filter totals matched the original Python business logic for all eight filters.
- SQL Server denied `SHOWPLAN` permission. Existing index metadata was reviewed; no index was added because the remaining cold filter uses leading-wildcard searches over text/LOB columns, which a conventional nonclustered index cannot accelerate.

## Release Decision

PP1 removes the Relevant Threats release blocker and meets both performance targets. The release candidate is ready for production verification.
