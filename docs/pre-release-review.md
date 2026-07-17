# CTI Dashboard v0.5.0-alpha Pre-Release Review

Review date: 2026-07-17  
Scope: Complete application code, templates, configuration, SQLAlchemy models, `database/init.sql`, collector framework, CISA KEV integration, CLI, and configured SQL Server integration.  
Review mode: Review plus narrowly scoped fixes for confirmed syntax/import/Flask/SQLAlchemy/route/template/CLI/model defects. No features, schema changes, commits, or pushes were performed.

## Executive result

The application is suitable for an alpha baseline commit after the corrected files are reviewed, but it is **not ready for production deployment**. Core imports, blueprints, GET routes, templates, SQL Server queries, model mappings, and collector CLI registration work. The principal production blockers are missing authentication/authorization, missing CSRF protection, an unsafe fallback secret/configuration policy, insufficient automated testing and deployment controls, and an unpaginated Threat list that already produces a roughly 2.9 MB response for 1,647 rows.

**Production readiness score: 56/100**

## Files changed by this review

Modified:

- `app.py`
- `config.py`
- `app/models/vendor.py`
- `app/models/threat.py`
- `app/vendors/routes.py`
- `app/threats/routes.py`
- `app/templates/base.html`
- `app/templates/threat_form.html`

Created:

- `docs/pre-release-review.md`

Other pre-existing working-tree changes were reviewed but preserved. No file was committed or pushed.

## Passed

- All 28 project Python files parse successfully.
- The application factory imports and creates the application without circular-import failure.
- SQLAlchemy is initialized once through `app.extensions.db`.
- Blueprints `auth`, `dashboard`, `threats`, and `vendors` register successfully.
- Ten expected Flask rules are registered; mutating delete routes accept POST only.
- All seven Jinja templates compile.
- Configured SQL Server GET checks returned HTTP 200 for `/`, `/vendors`, `/vendors/add`, `/threats`, `/threats/add`, and representative Vendor and Threat edit routes.
- `flask collector status` completed with exit code 0; `run`, `run-demo`, `seed-sources`, and `status` are registered under the collector CLI group.
- The dashboard KEV predicate compiles for SQL Server as `[Threats].[KEV] = 1`, not `IS 1`.
- Dashboard card and chart queries execute against SQL Server and use live Threat data.
- SQLAlchemy queries are expression-based/parameterized; no direct user-controlled SQL construction was found.
- Jinja autoescaping remains enabled, and no `safe` filter or `Markup` bypass was found.
- `.env` is excluded by `.gitignore` and is not tracked.
- CISA KEV uses the official JSON source, a timeout, one retry, collection-run status updates, item-level error isolation, and structured collection events.
- Actual SQL Server tables `Vendors`, `Threats`, `Sources`, `CollectionRuns`, and `SourceItems` exist and were readable.

## Review checklist

| # | Area | Result | Notes |
|---:|---|---|---|
| 1 | Python syntax | Pass | 28/28 files parsed. |
| 2 | Import errors | Pass after fix | Application and CLI imports succeed; duplicate dotenv import removed. |
| 3 | Circular imports | Pass | Deferred imports in the factory avoid cycles. |
| 4 | Unused imports | Pass with dependency warning | No confirmed unused Python imports remain; several installed packages are currently unused. |
| 5 | Unused variables | Pass | No confirmed unused local variables found. |
| 6 | Dead code | Warning | Empty auth/services/utils scaffolding and the demo collector remain intentionally dormant. |
| 7 | Duplicate code | Warning | Vendor validation, Threat form handling, and CLI result rendering contain repeatable patterns. |
| 8 | Blueprint registration | Pass | Four blueprints registered once. |
| 9 | Flask routing | Pass after fix | Route map is valid; FK-protected deletes now fail gracefully. |
| 10 | SQLAlchemy relationships | Pass | Declared relationships and foreign keys resolve. Relationships are minimal and lack cascade declarations, which is safe for current provenance retention. |
| 11 | SQLAlchemy model consistency | Pass after fix | SQL Server Unicode, DATETIME2, default, constraint, and length mismatches corrected. |
| 12 | Models vs init.sql | Pass after fix | All five mapped tables align on names, types, nullability, keys, principal checks, and defaults. |
| 13 | Collector registration | Pass | Demo and CisaKev collectors are registered; only CISA KEV is exposed as a production named run. |
| 14 | CLI registration | Pass | Collector group is attached in the factory and status executes. |
| 15 | Logging consistency | Warning | Collector events are JSON strings; web CRUD and startup have little operational logging and there is no centralized formatter/handler policy. |
| 16 | Exception handling | Warning | Collector isolation is good; CRUD add/edit commits do not translate database exceptions into user-safe responses. |
| 17 | Transaction handling | Pass with warning | Collector rollback paths and delete rollback paths are present. Per-item commits are reliable but expensive; add/edit race failures can still surface as 500 responses. |
| 18 | Duplicate detection | Pass with limitations | ExternalId, content hash, CVE, and CVE-less title paths exist. Database uniqueness prevents source-item races; Vendor/Threat identity checks can still race without database uniqueness. |
| 19 | Dashboard queries | Pass with performance warning | Correct SQL Server Boolean comparison and live aggregates; multiple full aggregates run per request and Threats has no supporting indexes. |
| 20 | Jinja templates | Pass after fix | All compile; corrupted menu glyphs were replaced with existing Bootstrap icons. |
| 21 | Bootstrap templates | Pass with warning | Layout is consistent. CDN assets lack SRI; Chart.js is not version-pinned. |
| 22 | Folder structure | Pass | Factory/package/blueprint/model/collector separation is coherent for the alpha scope. |
| 23 | Naming consistency | Warning | Database-style PascalCase model attributes coexist with Python snake_case; source type/CLI name values use separate conventions. |
| 24 | Configuration usage | Warning | Database URI and secret are environment-driven, but `.env` uses `override=True` and configuration is not validated at startup. |
| 25 | Hard-coded values | Warning | Insecure secret fallback, page size, severity list, source seed metadata, and collector defaults are embedded in code. Official feed URLs are acceptable constants. |
| 26 | Security | Blocked | See Production blockers. SQL injection and template autoescape checks passed; CSRF, auth, secret enforcement, and URL-scheme validation did not. |
| 27 | Performance | Warning | Vendor pagination works; Threat list is unpaginated. Collector performs repeated lookups and commits per item. |
| 28 | Production readiness | Not ready | Core alpha behavior works, but security, testing, operations, and performance gates remain. |

## Must Fix

### Corrected during this review

- Disabled forced Flask debug mode in the executable entry point.
- Removed the duplicate `load_dotenv` import.
- Aligned Vendor strings with SQL Server `NVARCHAR` and represented the `Enabled` server default.
- Aligned Threat date columns with SQL Server `DATETIME2` and represented the DDL CVSS check constraint.
- Aligned Threat Reference URL validation and HTML maximum length with `NVARCHAR(1000)`.
- Added foreign-key guards and `IntegrityError` rollback handling to Vendor and Threat delete routes. This prevents referenced records from becoming database-error HTTP 500 responses.
- Replaced corrupted navigation glyphs with Bootstrap icons and corrected the displayed alpha version.

### Remaining before production

- Add authentication and role-based authorization before exposing any CRUD route.
- Add CSRF protection to every POST form, including delete forms.
- Require a strong `SECRET_KEY`; remove the known fallback and fail closed when required production configuration is missing.
- Validate stored outbound URL schemes server-side and permit only safe HTTP/HTTPS links before rendering clickable references.
- Add Threat-list pagination or an equivalent bounded result strategy before production traffic.
- Establish an automated test suite and CI gate covering CRUD validation, duplicate behavior, delete constraints, collector partial/failure states, dashboard data, and SQL Server dialect behavior.
- Define a supported production deployment configuration, schema migration/release procedure, backups/restore test, TLS/reverse-proxy policy, and operational logging/monitoring.

## Warnings

- `load_dotenv(override=True)` can replace environment variables already supplied by a process manager, increasing configuration surprise in production.
- Add/Edit routes perform pre-checks followed by commits without catching `IntegrityError`; concurrent duplicate submissions can still result in a 500 and require session rollback.
- Manually entered Threat Reference URLs rely on browser `type=url` validation only; direct POST clients can store non-HTTP schemes.
- Manual Threat duplicate validation is title-only, which can reject distinct vulnerabilities sharing a title. Collector identity uses CVE first and is more appropriate.
- A collector update for a matching CVE overwrites canonical Threat fields; future multi-source precedence rules are not defined.
- Re-seeing unchanged source content changes `SourceItem.ProcessingStatus` to `Duplicate`, so the field describes the latest run outcome rather than durable processing history.
- A failed item is committed separately. This aids partial progress but can leave a very large number of short transactions and source-item records during a malformed feed event.
- Collection execution has no distributed lock/lease; concurrent CLI runs for one source can contend despite unique indexes.
- The settings navigation item is a nonfunctional placeholder.
- Bootstrap, Bootstrap Icons, and Chart.js are loaded from public CDNs without integrity attributes; Chart.js is loaded from an unversioned URL.

## Performance review

Observed against the configured database containing 278 vendors, 1,647 threats, seven sources, one collection run, and 1,647 source items:

- Dashboard: approximately 567 ms cold and 50 ms warm; response about 9 KB.
- Vendor list: approximately 39 ms cold and 14?17 ms warm; response about 15 KB.
- Threat list: approximately 513 ms cold and 297?332 ms warm; response about 2.94 MB.

The Threat list is the immediate scaling concern. The dashboard also executes five scalar aggregate queries plus two chart aggregates on every request. `Threats` has no dedicated indexes for severity, KEV, publication date, CVE, or vendor grouping. Index changes require a separately reviewed schema change and were not made here.

The collector deliberately commits each item, protecting partial progress but adding transaction and lookup overhead. Its Vendor, SourceItem, and Threat identity lookups are repeated per item; future volume testing should quantify N+1 and commit costs.

## Model-to-DDL alignment

- `Vendor`: `NVARCHAR(100/100/255)`, nullable columns, primary key, and `Enabled BIT DEFAULT 1` are represented.
- `Threat`: `NVARCHAR` lengths, `DECIMAL(4,1)`, `BIT DEFAULT 0`, `DATETIME2`, `NVARCHAR(MAX)`, Vendor FK, and CVSS range check are represented.
- `Source`: lengths, defaults, DATETIME2 fields, unique source name, and positive interval/timeout checks are represented.
- `CollectionRun`: FKs, DATETIME2 fields, defaults, status/count checks, and relationships are represented.
- `SourceItem`: lengths, DATETIME2 fields, defaults, status check, FKs, unique hash, and filtered external-ID uniqueness index are represented.

SQLAlchemy constraint/default names do not need to duplicate every SQL Server constraint name for runtime mapping. The application must continue to treat `database/init.sql` or a future migration system as the schema authority.

## Security review

- **CSRF:** Missing. All add/edit/delete POST routes are vulnerable to cross-site request forgery.
- **Authentication/authorization:** Missing. The auth blueprint is empty; all management actions are anonymous.
- **XSS:** Jinja autoescaping passes. The primary remaining risk is unsafe stored Reference URL schemes rather than HTML interpolation.
- **SQL injection:** No finding. User filters and values use SQLAlchemy expressions/binds, and Vendor sorting uses an allowlist.
- **Secrets:** Database credentials are read from environment configuration and `.env` is ignored. The default Flask secret is public and unsafe.
- **Debug mode:** Forced debug mode was removed. Deployment must still ensure `FLASK_DEBUG` is disabled.
- **External collection:** CISA fetch has timeout/retry behavior. Egress policy, proxy settings, certificate policy, and maximum payload size are not centrally governed.

## Recommended

1. Resolve every Production blocker before labeling the application production-ready.
2. Add isolated unit tests plus SQL Server integration tests; use disposable test data/schema for mutation tests.
3. Introduce a migration tool and release procedure instead of relying only on an idempotent initialization script.
4. Bound list/chart queries and add indexes based on measured SQL Server execution plans.
5. Centralize logging with correlation/run identifiers, environment-appropriate handlers, rotation/retention, and secret redaction.
6. Add idempotency/concurrency tests for simultaneous collector runs and duplicate Vendor/Threat creation.
7. Pin front-end asset versions and use SRI or serve vetted static assets locally.
8. Remove currently unused dependencies (`pandas`, `feedparser`, `msal`, and `openpyxl`) until their features are implemented, reducing install size and attack surface.

## Technical Debt

- Minimal README with no setup, deployment, database, testing, or recovery instructions.
- No automated tests, CI configuration, lint/type-check configuration, or coverage target.
- No migration history or schema-version table.
- Repeated validation and CLI output code.
- Empty `auth`, `services`, and `utils` package scaffolding.
- Mixed database/Python naming conventions.
- Demo collector and planned disabled source seeds share production collector code paths.
- No retention policy for `CollectionRuns`, `SourceItems`, raw content, or collector logs.
- No explicit data ownership/merge policy when future sources describe the same CVE.

## Production blockers

1. Anonymous write/delete access (no authentication or authorization).
2. No CSRF protection on state-changing web requests.
3. Public fallback session secret and no fail-closed production configuration validation.
4. Unsafe server-side acceptance of arbitrary Reference URL schemes.
5. Unbounded Threat list response and unproven performance at production volume.
6. No automated regression/integration test gate.
7. No documented and tested production deployment, database migration, backup/restore, monitoring, or incident rollback process.

## Verification record

- Python AST parse: 28 files passed.
- Application import/factory creation: passed.
- Jinja compile: seven templates passed.
- Blueprint registration: `auth`, `dashboard`, `threats`, `vendors` passed.
- Route registration: ten rules passed; delete routes are POST-only.
