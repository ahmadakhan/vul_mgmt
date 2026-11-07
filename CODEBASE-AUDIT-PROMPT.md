# VulnStream-Enterprise — Complete Codebase Audit Prompt (Accuracy-Verified)

You are a senior full-stack SRE, security engineer, production-readiness reviewer, and UI/UX auditor. Audit the VulnStream-Enterprise codebase to determine whether it is safe to deploy and operate in production, and whether every page of the user interface works and looks professional. Audit and fix the whole codebase: server, database, delivery, ML, search, pipeline, and the React SPA. Focus on deployability, operability, resilience, security, data integrity, observability, and feature completeness of implemented features. Do not report missing features; evaluate existing code quality and completeness of implemented features.

## System Overview (verified against package.json, src/design/pages.ts, server/db.ts, server/migrations/)

- **React 19 + Vite SPA** (`src/`), **Node.js >=26.0.0 + Express API/worker** (`server/`), **PostgreSQL 17**, Docker Compose + Caddy TLS proxy
- **Bootstrap**: `server/main.ts`; router: `server/app.ts`; health: `/live`, `/ready`, `/metrics`
- **Migrations**: `server/migrate.ts`, **`server/migrations/001..037`** + **`server/migrations/indexes/`** (concurrent index files). `REQUIRED_SCHEMA_VERSION = 37` (`server/db.ts:124`) enforced at production startup; must match the highest `NNN_*.sql` file.
- **Env validation**: `server/config.ts` (Zod schemas, `ENCRYPTION_KEY` base64 32-byte via regex `/^[A-Za-z0-9+/]{43}=$/`, production-gated checks). Production requires HTTPS `APP_ORIGIN` unless `ALLOW_INSECURE_HTTP` for private/Tailscale IPv4 origin; `FAULT_SIMULATION_ENABLED` blocked in production; `HEARTBEAT_URL` https-only in production, no embedded credentials; `TRUST_PROXY` rejects trust-all values.
- **Database**: `server/db.ts` (pg pool, `statement_timeout`, audit hash chain `chainAuditLogs`, `transaction` with advisory locks, `state_metrics` table for bounded counts)
- **ML subsystem**: `server/ml/` (algorithms, models — 18 models, runtime, train, integration, cron)
- **Email delivery**: `server/delivery.ts`, `server/emailProviders.ts`, `server/dailyDigest.ts`
- **Vulnerability search**: `server/vulnerabilitySearch.ts`, `server/googleCse.ts`, `shared/vulnerability.ts`
- **Correlation engine**: `server/correlation/` (inventory, runtime, operations, stream, heartbeat, metrics)
- **Pipeline engine**: `server/pipeline.ts`, `src/engine/pipelineEngine.ts`
- **Frontend**: `src/components/` (48+ views), **`src/design/pages.ts` (exactly 24 pages)**, `src/context/`, `src/hooks/`, `src/utils/`, `src/engine/`, `src/types/index.ts`
- **Shared**: `shared/correlation.ts`, `shared/state.ts`, `shared/vulnerability.ts`, `shared/watchlistIdentity.ts`
- **Tests**: **69 test files** under `tests/` (node --test + vitest), `tests/fixtures/`
- **Config/ops**: `.env`, `.env.example`, `.env.test`, `compose.yaml`, `Dockerfile`, `Dockerfile.test`, `docker-compose.test.yml`, `OPERATIONS.md`, `AGENTS.md`

## Running the app for UI verification

- **API server**: port 8080 (`npm run dev:server` → `node scripts/free-port.mjs 8080 && tsx watch --env-file=.env server/main.ts`)
- **SPA**: port 3000 (`npm run dev`), which **proxies `/api` to 8080** (`vite.config.ts`). `APP_ORIGIN=http://127.0.0.1:3000` in `.env` — the API rejects mutations whose `Origin` is not `APP_ORIGIN`, so **login through :8080 directly fails with 403**; always drive the app through :3000.
- **Every page is client-side rendered** behind one login. Navigation is by clicking sidebar labels from `src/design/pages.ts`. To audit all pages, log in with a real account (create one with an elevated connection if none exists, then delete it afterwards) and click through every sidebar entry.
- Verify with a headless browser: console errors, failed network requests, stuck loaders, crashed views, horizontal overflow at 390/820/1024/1280/1440/1920 px, and screenshots you actually look at. Geometric claims (overlap, clipping) must be measured with `getBoundingClientRect` — a screenshot crop is not proof of a layout bug.

## 24 pages registered in src/design/pages.ts (audit every one)

dashboard, watchlist, findings, threat-intelligence-search, vulnerability-search, threat-data, threat-analytics, cpe-matcher, advisories, correlation, pipeline, alerted-cves, feeds, recipients, template, daily-digest, emails, email-queue, action-center, archive, logs, health, aliases, settings

## Prior audit context (do not re-report already-fixed items unless they regress)

The codebase has undergone multiple audit passes. Known fixed areas include: delivery false positives/negatives, stale-bundle recovery, CPE wildcard bypass, provider confirmation, real cancellation via AbortSignal, digest-window index, outbox isolation, concurrent-query-on-single-client fix, template XSS escaping, retention advisory-lock fix, stuck-promise guard releases, ML quality gate, pipeline hardening, fail-closed command authorization, unauthenticated `/api/state`, resend subscription governance, retention claim TTL, ML training cross-replica claim, digest lock-connection failure flags, daily-digest lock-event spam, Mailgun egress hosts, legacy ciphertext envelopes, stale seeded feed URLs, RSS XXE-guard false positives, unbounded execution-table scans, webhook blank-keeps, findings/ActionCenter/EmailQueue layout defects. Verify these fixes still hold and look for regressions, edge cases, and uncovered paths.

## Audit Dimensions

### 1. Boot & Lifecycle (`server/main.ts`, `server/app.ts`)

- Graceful startup, migration ownership, DB role privileges, signal handling (SIGTERM/SIGINT), connection pool close, worker pool drain, hang timer `unref`
- Readiness `/ready`: DB latency, supervisor health, backpressure; must fail closed when DB unavailable
- Liveness `/live`: event-loop hang detection threshold
- Graceful degradation when optional services missing
- Process global handlers: `uncaughtException`, `unhandledRejection`; structured logging
- Worker tick loop: stuck-promise detection, generation tracking, non-overlapping execution
- Retention, daily digest, ML training schedulers: claim/release, stuck detection, bounded retry
- Session/login-attempt/password-reset token cleanup: interval, expiry enforcement
- Shutdown deadline: 30s forced exit vs graceful pool close; await in-flight promises
- `listenWithRetry` EADDRINUSE handling; never terminates conflicting process

### 2. Configuration & Secrets (`server/config.ts`, `.env.example`, `server/secrets.ts`)

- All required env vars documented; defaults safe for production
- No hardcoded secrets; `ENCRYPTION_KEY` validation (base64 32-byte via Zod regex); `ENCRYPTION_KEYS` (up to 16 comma-separated keys); credential blank-keeps behavior
- Ciphertext envelope compatibility: `decrypt()` must accept both current and legacy envelope forms
- `METRICS_TOKEN` 32+ chars in production
- Egress allowlist `EGRESS_ALLOWED_HOSTS` + `EGRESS_ALLOWED_HOSTS_EXTRA`; `DEFAULT_EGRESS_HOSTS`; redirect target SSRF re-validation
- `TRUST_PROXY` rejects trust-all values (`true`, `*`, `0.0.0.0/0`, `::/0`)
- CORS restrictive, origin validation, CSRF
- Rate limiters DB-backed shared across replicas (reset quotas, mutation quota, ingest quota)
- SMTP/API provider config validation; encrypted creds at rest; `decrypt()` failure handling
- `FAULT_SIMULATION_ENABLED` blocked in production; `HEARTBEAT_URL` https-only in production, no embedded credentials
- `APP_ORIGIN` HTTPS in production, origin without path (Zod validates `origin.origin === APP_ORIGIN`)
- `POOL_STATEMENT_TIMEOUT_MS`, pool sizing, idle/max lifetime

### 3. Database & Migrations (`server/db.ts`, `server/migrate.ts`, `server/migrations/`)

- Migration job owns DDL; runtime role no DDL; idempotent migrations; reversible where feasible
- `REQUIRED_SCHEMA_VERSION = 37` enforced at production startup, matching highest `NNN_*.sql` file
- Connection pooling: size, timeout, leak prevention, `release()` in finally with failure flag
- Transactions for critical ops (outbox, findings, aliases); advisory locks scoped per schema
- Index coverage for hot queries; `CREATE INDEX CONCURRENTLY` outside transaction (index files live in `migrations/indexes/`, version markers in `migrations/`)
- Invalid index detection and rebuild before concurrent build
- No N+1 in loops; batch queries (`putMany`, `removeMany`, `getMany`)
- `FOR UPDATE` row locks for read-modify-write; alphabetical lock ordering to prevent deadlocks
- Audit chain: tamper-evident hash chain, runtime role cannot update/delete
- `statement_timeout` per pool (15s default); migrations use 300s local timeout
- `transaction()` with `AbortSignal` cancels backend from second connection; drops socket when cancel undeliverable
- One client, one query at a time (no `Promise.all` over queries on a single transaction client)
- No unbounded `list(kind)` scans on hot paths — active/queued record lookups must be bounded queries with supporting indexes; `state_metrics` used for `/api/state` counts

### 4. Security (all server routes, `server/auth.ts`, `server/validation.ts`, `server/network.ts`)

- SQL injection: parameterized queries only; no string interpolation in SQL
- XSS: escaped HTML in advisory/email templates (`escapeHtml`); template compiler token sanitization; preview HTML sanitised client-side before `dangerouslySetInnerHTML`
- CSRF/origin on state-changing endpoints; `__Host-` cookie prefix in production
- Auth: opaque sessions, password hashing (scrypt), expiry, reset quotas, login throttling
- RBAC on every route (`requireRole`); `requireAuth` fail-closed; every state-bearing read endpoint authenticated (including `/api/state`)
- Input validation (zod) on all endpoints; strict schemas; no implicit `any`
- SSRF: URL validation in `resolvePublic`; public IP check; port 443 only; no URL credentials; redirects disabled for provider confirmation lookups
- Path traversal in file ops (`disableFileAccess`, `disableUrlAccess` in nodemailer)
- Dependency audit (`npm audit`)
- Sensitive data redaction in events (`describeError` context redaction)
- Password reset: per-IP and per-account quotas; code expiration; consume-once; account disabled check
- Session renewal rotates CSRF token; logout clears `__Host-` cookie with matching attributes
- `/api/system-uptime` public endpoint; no sensitive data leakage
- Subscription governance on every dispatch path (`recipientAllows` on queue, resend, and follow-up alike)

### 5. Resilience & Concurrency (`server/delivery.ts`, `server/pipeline.ts`, `server/retention.ts`, `server/correlation/`)

- Retry with exponential backoff + jitter for external calls; `Retry-After` honor
- Circuit breakers for feeds/pipeline; feed recovery; dead-letter queue
- Worker coordination: dedup, advisory locks, lease ownership, dead-letter
- Shared state safety; cache invalidation
- Outbox at-least-once; content dedup; stable Message-ID/idempotency keys
- Digest state durable in PG
- `AbortController` for retention/digest; `cancelBackend` for stuck statements
- Pool connection destroy on failure flag; broken connections not recycled
- Stuck promise detection (15 min backstop) for pipeline/outbox/digest/retention/training
- ML training never overwrites active model on failure; quality gates; cross-replica claim TTL honoured and released on failure
- Error handling: `allSettled` for partial source failures; non-blocking writes
- Delivery: prior-attempt consultation before re-send; `MAIL_CONFIRM_BEFORE_SEND`; provider confirmation lookup; `transportRejected` flag; everyone-group deferral
- Pipeline: stale-bundle detection, `rebuildFromCurrentInventory`, advisory lock schema-scoped, interrupted `RUNNING` recovery, poison-pill cap

### 6. Performance & Scale

- Memory leaks: listeners, timers, buffers, model history; `timer.unref()` on interval timers
- Bundle size; code splitting; Vite build (manualChunks for react/lucide/motion)
- Pagination on all list endpoints; cursor pagination for logs
- Query performance; indexes; `ROW_NUMBER()` window for bounded heavy collections
- Concurrency limits (`workLimiter`); mutation rate limiter shared across replicas
- CPE cache bounded (DoS fix); memory shedding under load
- Feed max duration; request timeouts; socket timeouts
- `unref()` on non-critical timers to allow process exit
- Digest-window index bound on `created_at` (not just `kind`)
- Table scans driven by JSONB status predicates are indexed (see migration 035 / indexes dir)

### 7. Observability (`server/events.ts`, `server/logging.ts`)

- Structured logging with levels; operational events (category/level/full-text)
- Hash-chain audit trail immutability (runtime role cannot update/delete)
- Metrics endpoint auth (`METRICS_TOKEN`, 32+ chars)
- Health reflects actual DB/process/worker measurements (no inferred external)
- `describeError` with stack, cause, code, detail; bounded text
- Event log pagination; cursor-based; category filtering
- DB severance detection; memory-shedding HIGH-lane floor; hang detection
- Dead-letter queue spool capacity alert (`dead_letter.spool_exhausted`)
- No per-tick no-op event spam

### 8. Delivery & Email (`server/delivery.ts`, `server/emailProviders.ts`, `server/dailyDigest.ts`, `src/components/EmailQueueView.tsx`, `EmailHistoryView.tsx`, `ActionCenter.tsx`)

- SMTP/API providers; encrypted creds; leave-blank keeps
- Retry policy defaults (6 attempts, 1m initial, 1h cap); max attempts 1 disables retries
- Provider acceptance recorded as `ACCEPTED` (not inbox proof)
- Digest combining; per-recipient tier filtering
- Manual retry; queue test email
- PDF attachment: graceful degradation on render failure
- Prior-delivery confirmation to prevent duplicates; `transportRejected` flag
- Content revision for dedupe; `deliveryRevisionEvidence` canonical builder
- Everyone-group deferral until Security-team delivery confirmed
- Bulk operations (retry, cancel, send now); auto-refresh every 30 seconds
- Permissions: ADMIN or OPERATOR role for management actions

### 9. ML Subsystem (`server/ml/`)

- Offline-only; fallback when untrained
- Training never overwrites active model on failure; quality gates
- Drift detection (PSI, concept drift)
- Cron training script; data provider matches schema
- Memory in history buffers; type safety
- `initMlRuntime` failure does not block server start
- Scheduled training interval; last-run dedup; cross-replica claim with TTL
- `computeFeedRecoveryDelay` integration

### 10. Frontend Production & UI Page Audit (`src/`) — every page, in a real browser

The SPA has exactly **24 pages** registered in `src/design/pages.ts`. Audit **every one of them** by driving the running app (see "Running the app for UI verification" above), not by reading JSX:

- **Functional**: each page renders real content (no stuck loader, no ErrorBoundary crash, no zero-content main region), and its data loads from the API without failed requests
- **Console & network**: zero console errors beyond the expected pre-login `/api/session` 401 probe; zero failed requests
- **Layout**: no column collapse (a table cell rendering one character per line), no text clipped without a tooltip affordance, no buttons wrapping mid-label, no horizontal page overflow at 390–1920 px — tables scroll inside their own container instead of squeezing
- **Readability**: long identifiers/titles/subjects either wrap over multiple lines or truncate with a `title` attribute; timestamps and mono columns are `whitespace-nowrap`
- **ErrorBoundary** recovers; loading states; empty states
- Theme compatibility (dark + light), responsive tables, modal focus management
- React 19; strict mode considerations
- CSRF token handling on mutation endpoints; session expiry handling (401 → login flow)
- Cursor pagination in UI tables; real-time SLA monitoring (ActionCenter)
- When a defect is found: fix it, then **re-screenshot the same page** to confirm the fix — and check the fix did not introduce a new defect in an adjacent column

### 11. Deployment (`Dockerfile`, `compose.yaml`, `Dockerfile.test`, `docker-compose.test.yml`, `scripts/`)

- Dockerfile security (non-root, minimal); docker-compose; Caddy TLS
- Migration service before app
- Healthchecks in compose
- Ports not published directly (app on internal network)
- Backup/restore tested (`OPERATIONS.md`)
- `ATTACH_ADVISORY_PDF` toggle; Chrome executable path
- `server-dist/` build output; `build-server.mjs` bundling
- `scripts/build-server.mjs`, `scripts/supervisor.mjs`, `scripts/free-port.mjs`

### 12. Vulnerability Search & OSINT (`server/vulnerabilitySearch.ts`, `server/googleCse.ts`, `shared/vulnerability.ts`)

- External API calls (OSV/NVD/CISA KEV/Google CSE) must have timeouts, retries, egress allowlist, rate limits
- Input validation and SSRF protection on search queries
- Caching bounded (CPE cache DoS fix); memory shedding under load
- Secrets (API keys) encrypted/not leaked
- NVD key rejection caching (10 min TTL); anonymous fallback
- CISA KEV cache with in-flight dedup; 10 min TTL
- OSV 404 = empty answer, not failure; NVD 404 = empty answer
- Partial results via `Promise.allSettled`; one slow source must not hold page hostage

### 13. Pipeline Hardening (`server/pipeline.ts`, `src/engine/pipelineEngine.ts`)

- Transaction-scoped advisory locks; shared worker connection stop; news dedup by asset identity
- Verify no race conditions in watchlist/recipients mutations
- Alias lifecycle: self-maintaining but bounded; 30-day expiry for automatic rows
- Correlation schema contract (migrations 023-028)
- Match quality gate; precision/recall regression test
- Pre-CVE disposition inheritance; two whole-table scans removed; retention takeover loop fixed
- Applicability matching time-bound: `scopeHours` from run settings bounds matching; deliberate exceptions use `scopeHours: 0` (delivery revalidation, daily digest rematch)

### 14. Threat Feeds & Recommended Catalog (`server/recommendedFeeds.ts`, `server/ingestion.ts`, `server/rss.ts`)

- Bootstrap repairs seeded feed URLs from the catalog (feeds whose id exists but whose source URL was corrected get the new URL, credentials preserved); verify reconciliation runs at boot and DB URLs match `RECOMMENDED_FEEDS`
- Every recommended feed URL verified live before commit: HTML/404/403 to service user agent must not ship enabled; document reason and leave disabled rather than seeding broken
- RSS parser XXE guard: character references must NOT be decoded before declaration check; live `<!ENTITY` and `<!DOCTYPE … SYSTEM/PUBLIC` refused
- New feed hosts added to default egress allowlist (`server/config.ts` `DEFAULT_EGRESS_HOSTS`) or feed fails at connect time
- Distinguish code defects from environmental failures before "fixing": probe URL from deployment host, test service UA vs browser UA, check TCP vs TLS

## Output Format

For each finding:

- **File:** `path:line`
- **Severity:** CRITICAL/HIGH/MEDIUM/LOW
- **Category:** Security/Resilience/Performance/Operability/DataIntegrity/UI/Testing/Deployment
- **Description**
- **Impact**
- **Fix**
- **Effort:** S/M/L/XL

## Priority Order

1. Security vulnerabilities
2. Data loss/corruption
3. Availability/reliability
4. Broken UI pages or unreadable data (functional/layout)
5. Operational gaps (health, logging, shutdown)
6. Performance
7. Deployment/config
8. Test coverage

## Exclusions

- `node_modules/`, `dist/`, `server-dist/`
- Linter-handled style (prettier)
- Generated migration content
- Missing features not in the codebase
- Environmental failures proven not to be code: CDN IP blocks, upstream 429s requiring paid tiers, network-level TLS interception — report as operator notes, not defects, after ruling the app out with the probes above

## Verification Commands

- `npm run lint` — `tsc --noEmit` (run before every commit)
- `npm test` — `node --import tsx --test --test-concurrency=1 tests/*.test.ts` (all tests)
- `npm run test:unit` — alias of `npm test`
- `npm run test:ci` — requires `TEST_DATABASE_URL`
- `npm run build` — client + server build
- `npm audit` — dependency vulnerabilities
- `npx vitest run tests/ml-*.test.ts --no-coverage --reporter=verbose` — ML subsystem only
- `node --import tsx server/ml/train/cron.ts` — ML training cron (standalone)
- UI: drive `http://127.0.0.1:3000` in a headless browser through login and all 24 pages; capture console errors, failed requests, per-breakpoint overflow, screenshots

## Deliverable

Produce a final audit report grouped by dimension with a severity count summary, then implement all CRITICAL and HIGH fixes. For UI findings, fix the component and re-verify the page in the browser. After implementing, run `npm run lint` and `npm test` to verify no regressions, and confirm every page still renders without console errors.