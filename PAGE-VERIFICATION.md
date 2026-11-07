# Page and watchlist verification — 21 October 2026

Checked the built application against an isolated PostgreSQL 17 database. All data used
here was explicitly labeled disposable test data. No production records were modified and
no external messages were sent.

## Page checks

All 14 navigation views rendered with populated application state, without a rendering error:

| Page | Verified |
| --- | --- |
| Dashboard | Inventory/findings/advisory counts, confirmed and review-required statuses |
| Monitored Products | Eight persisted assets, CPE and PURL display, inactive state, package-only asset edit |
| Matching Simulator (inventory subview) | Rendered controls, affected version matches, fixed boundary excludes, unknown version requires review |
| Vulnerabilities | Four expected findings, detail drawer, status edit, persistence after reload, status filter |
| Threat Cache | Two normalized test CVEs |
| Advisories | Generated bulletin, transport status, detail view and affected assets |
| Executions | Completed runs and measured phase details |
| Sent History | Registry populated from mocked transport acceptance |
| Threat Feeds | Disabled configured feed and its actual status |
| Recipients & Webhooks | Configured test recipient and channel tabs |
| HTML Template | Sandboxed neutral-example preview and customization controls render |
| Delivery Log | Mock transport acceptance record renders |
| Audit Trail | Persisted events, hash-chain verification passes, pagination advances |
| System Health | Database and worker state render |
| Settings | Stored configuration and server operator controls render |

Login and expired-session handling were also exercised. Page checks are navigation and selected workflow checks; they do not imply every button/provider integration has been externally tested.

## Persisted watchlist matrix

Two normalized test CVEs use the affected interval `>=1.0, <2.0`, one for a CPE and one for a PURL. Fixture preparation uses authenticated API writes and the actual server pipeline/outbox. Mail acceptance is injected locally, never sent.

| Inventory | Expected and observed |
| --- | --- |
| CPE widget 1.5 | Confirmed finding |
| CPE widget 2.0 | No finding (fixed boundary) |
| CPE widget unknown version | Review-required finding; excluded from dispatch |
| Different CPE product | No finding |
| Inactive CPE inventory | No finding |
| PURL dependency 1.5 | Confirmed finding |
| PURL dependency 2.0 | No finding |
| PURL dependency without version | Review-required finding; excluded from dispatch |

Observed four findings: two confirmed and two review-required. Only the two confirmed findings entered the advisory. A repeat run retained four findings and one advisory: no duplicates. Browser simulator independently produced the same affected/excluded/review behavior for CPE versions 1.5, 2.0 and `*`.

## Defects fixed during these checks

- Strict CPE matching no longer substitutes marketing aliases for different canonical products.
- Empty per-CPE metadata falls back to the supplied CPE criteria.
- Versionless packages produce review findings for ranged vulnerabilities.
- Unknown architecture/context cannot confirm a constrained vulnerability.
- CPE builders preserve canonical hyphens (for example `pan-os`).
- The previously blank Matching Simulator now renders and uses the server's pure correlation engine, without fabricated dispatch or unsigned VEX suppression.
- Inventory editing uses parsed canonical identifiers, preserves untouched CPEs and does not add artificial CPEs to package-only inventory.
- Finding actions wait for successful API writes before closing; missing vendor URLs no longer link back to the app.
- Dashboard review-required findings no longer claim automatic delivery; advisory timestamps are labeled as generation dates.

## Automated validation

`npm run lint`, `npm run build`, and the full test suite with `TEST_DATABASE_URL` passed:
**42 tests, zero failures, zero skips**. Five new regression tests reproduced failures
before the matching/builder fixes and passed afterward. The disposable persisted matrix is
reproducible through `tests/fixtures/prepareBrowser.ts` with `NODE_ENV=test` and a fresh
database named `vulnstream_pages`; this is an explicitly invoked fixture, not production
startup logic.

Screenshot: [watchlist-matching-verification.png](watchlist-matching-verification.png).
It shows the simulator reporting a review-required match for an unknown installed version.

Live feed availability, real SMTP/webhook delivery and target-environment load are
outside this local page/matching check.
