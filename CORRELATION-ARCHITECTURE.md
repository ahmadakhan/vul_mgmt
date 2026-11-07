# Native advisory correlation audit and implementation

This change adds an independent native-table ingestion path to the existing VulnStream
application. It preserves the record-store inventory, existing CVE applicability engine,
RSS parser, delivery outbox, authentication, CSRF checks, SSRF controls, and process
shutdown handlers. It projects operator-managed inventory into an isolated
application-owned table. Owner-managed native inventory rows are read without rewriting
them.

## Audit findings and resolved gaps

| Finding | Resolution |
| --- | --- |
| Existing application inventory and intelligence are stored in `records`, rather than the requested native relations | Add guarded native relations and isolate their ingestion and matching contracts; do not change existing record-store behavior |
| No dedicated streaming correlation worker with native-table transactions | Bounded NDJSON/object stream processor, shared concurrency admission, per-item tracking IDs and transactional matching |
| No native fingerprint gate or separate low-confidence persistence | Unique URL/fingerprint indexes, insert-conflict gate, and isolated review buffer |
| Regex execution on the main event loop cannot be interrupted by a timer | Disposable worker threads with a 200 ms execution watchdog, 2-second startup limit and worker heap limit |
| Vendor revisions cannot safely be reduced to upstream SemVer | Preserve existing vendor-aware comparator; new native matcher uses conservative SemVer evaluation and routes ambiguous backports to review |
| No encrypted offline dead-letter fallback | Authenticated encryption with the existing AES-256-GCM utility, fsynced spool files, bounded disk use and automatic DB flushing |
| No native stream supervision or controls | Heartbeat probes, memory hysteresis, per-task cancellation, bounded queue admission, persistent pending jobs and authenticated dashboard |
| Existing mutation limiter restored tokens after allowing a request | Migration 012 exits the PL/pgSQL function immediately after its successful result; existing replica-sharing tests now pass |

The configured local database initially exposed none of `assets`, `unstructured_advisories`,
or `vendor_product_aliases` and was at schema version 4. It has now been upgraded to
version 14. Both existing inventory records were projected, and a before/after digest
verified that their stored data remained unchanged. See `correlation-deployment-report.json`.
All test and benchmark records used disposable schemas.

## Eight implementation layers

| Layer | Files | Behavior |
| --- | --- | --- |
| 1: PostgreSQL | `server/migrations/011_text_correlation.sql` | Guarded tables, partial identity
  indexes, lowercase composite lookup, generated TSV/GIN search, seeded aliases, separate
  match/review/dead-letter/pending dimensions. Index builds live in
  `server/migrations/indexes/` and are applied `CONCURRENTLY` outside the migration
  transaction by `applyIndexMigrations()` |
| 2: Boundaries | `server/correlation/validation.ts`, `deadLetter.ts` | Strict Zod safe parsing;
  200/255/50,000 title/URL/body limits; HTTP(S) URLs without credentials; encrypted
  malformed-input capture |
| 3: Correlation | `extraction.ts`, `engine.ts` | Exact structured CPE/PURL intersection,
  indexed alias n-grams, canonical vendor/product matching, bounded version extraction,
  strict CVE extraction, density-based early intelligence detection |
| 4: Version and confidence | `version.ts`, `engine.ts` | Explicit comparison bounds,
  preserved prereleases, uncertain backports reviewed, explicit-range exclusions cannot
  be overridden by aliases |
| 5: Transactions | `ingest.ts`, `query.ts` | Dedicated client; READ COMMITTED; atomic conflict
  gate; rollback; broken-client destruction; three retries after the initial attempt with
  exponential backoff and jitter |
| 6: Streaming and telemetry | `stream.ts`, `telemetry.ts` | Async iteration, bounded
  framing, global admission ceiling shared by concurrent streams, item metrics, bounded
  JSON stdout queue and viewer ring |
| 7: Recovery | `supervisor.ts`, `runtime.ts`, `server/main.ts` | Heartbeats, memory shedding,
  DB recovery, leased durable jobs, 15-second item cancellation and safe process restart
  on uncaught failures |
| 8: Dashboard | `src/components/CorrelationDashboard.tsx`, `shared/correlation.ts` | One-second
  polling, metrics, controls, fault simulation, NDJSON submission, following JSON console,
  searchable HIGH/MEDIUM match table |

Root TypeScript compilation now enables `strict`. Existing modules also passed that check.

## Protected database contract

Migration 011 contains no `ALTER TABLE`, `DROP`, column replacement, or owner-data
updates. It seeds missing aliases without overwriting existing mappings. It adds
indexes to the three protected tables. Those indexes are built with `CREATE INDEX
CONCURRENTLY` by `applyIndexMigrations()` on an autocommit connection, after the
schema transaction commits: a plain `CREATE INDEX` takes `SHARE` for the whole build,
and ingest workers run under a 3500 ms statement timeout, so an inline build converts
a deploy into a dead-letter backlog rather than a latency spike. The runner retries a
contended build (`55P03`/`40P01`), drops the invalid index a cancelled `CONCURRENTLY`
build leaves behind, and skips the trigram index when `gin_trgm_ops` is not resolvable
on the session path. An interrupted build was previously invisible;
`correlationPreflight()` and migration 024 reject any unique index whose `indisvalid`
is false.

The native contract is:

- `assets`: UUID `id`, text-compatible `vendor`, `product`, `version`, `cpe_23`, `purl`.
- `unstructured_advisories`: UUID `id`, `title`, `content`, `url`, `fingerprint`, tsvector `tsv_content`, timestamp `processed_at`.
- `vendor_product_aliases`: text-compatible `alias`, `vendor`, `product`.

Migration checks required column names and fails with an actionable message if they are absent. It cannot safely infer undocumented column mappings, conflicting data types, additional mandatory columns, or how an owner-managed TSV is maintained. Compare this contract with the actual target database before deployment. Incompatible protected tables require an explicitly approved adapter rather than automatic alteration. Unique index creation also fails safely if existing URL/fingerprint data contains duplicates.

B-tree lookups are indexed logarithmic operations, not a mathematical O(1) guarantee. GIN search cost depends on term selectivity and result volume.

## Input and matching behavior

`AdvisoryIngestor.processIncomingAdvisory(rawInput, pool)` accepts the validated object
shape: `title`, `content`, `url`, optional `cpes`, optional `purls`, optional `entities`.
Each entity contains `vendor`, `product`, and an optional `affectedRange`, such as
`>=1.0 <2.0`. Unknown fields are rejected. URL tracking parameters and fragments are
canonicalized before fingerprinting. SHA-256 hashes the unambiguous JSON tuple `[url,title]`;
the URL constraint separately enforces one stored article per canonical URL. A changed
title on the same URL remains a duplicate, as required by the URL uniqueness contract.

`AdvisoryStreamProcessor.processAdvisoryStream(readable, concurrencyLimit, pool)`
accepts object-mode records or UTF-8 NDJSON. Byte-stream frames are bounded to 256 KiB.
Multibyte characters can cross arbitrary chunk boundaries. Malformed bounded frames
retain their original frame inside encrypted dead letters; oversized frames retain a
rejection marker instead of unbounded input. Upstream object-mode producers must
likewise supply bounded records; the processor cannot undo memory already allocated by
an upstream producer. No per-stream array or promise list grows with total input size.

Product aliases are matched against bounded token n-grams using the alias functional
index. An exact alias maps to its dictionary vendor/product pair. Adjacent
affected-version language can qualify only an unambiguous single-alias article. Explicit
structured entity ranges override versionless aliases. Multi-product prose never
broadcasts one inferred version range to all products. Native vendor/product token
coincidence without a dictionary entity stays LOW.

HIGH means explicit structured identity intersection or a supported affected-range
match. MEDIUM means canonical vendor/product identity with security context and
unspecified versions. These are evidence confidence levels, not proof of exploitation or
source authenticity. LOW results, including unmatched early intelligence and ambiguous
backports, go exclusively to `low_confidence_review_buffer`. Native notification delivery
is connected to the existing outbox, retries, recipient controls and email review screen.
The administrator must explicitly enable its policy; activation starts with new matches
rather than broadcasting historical data. HIGH evidence can reach enabled ALL_SEVERITIES
recipients and ALL-event webhooks. MEDIUM email always waits for security approval, and
EVERYONE recipients retain their additional review gate. LOW evidence never enters
delivery automatically. Unscored intelligence cannot bypass critical-only or KEV-only
subscriptions. Stored inventory revisions are checked again before transport, so
disabled, deleted or changed inventory invalidates stale jobs.

RSS articles are handed to `correlation_pending` in the same transaction as their
accepted source checkpoint. This bridge reuses the existing parser's bounded summary.
The direct NDJSON path accepts up to 50,000 characters of advisory content. Parsing a
multi-gigabyte RSS XML document is not supported by the existing 8 MiB RSS parser; use
bounded feed pages or the new record stream for bulk datasets.

## Runtime and recovery

The main process starts the native consumer when `WORKER_ENABLED=true`; monitoring
remains available when the consumer is disabled. Claims use `FOR UPDATE SKIP LOCKED`
and a 60-second lease. A crash leaves the job available for retry. Unique article
constraints protect against duplicate effects after lease expiration or an uncertain
COMMIT acknowledgment. A failed durable dead-letter capture leaves the pending job
unacknowledged.

The supervisor halves configured concurrency once memory pressure is confirmed on two
consecutive probes at 85%, and pauses admission until memory falls below 60%. A single
sample is a transient allocation spike, not sustained pressure, so it only arms the
guard. HIGH priority keeps a floor of `max(2, ceil(desired/4))` workers while shedding:
halving the global ceiling otherwise rounds its share down to one slot and starves
exactly the critical advisories shedding exists to protect. The global ceiling and the
HIGH pool still bound it. Pressure is the higher of V8 heap usage against the heap
limit and RSS against a detected container memory limit. Optional exposed GC is invoked
when available. This is admission control, not a way to recover from a fatal V8
allocation failure.

Database outages pause admission. Failed transaction clients are destroyed, and
heartbeats retry connectivity. `DATABASE_URL` must point at the deployment's writable HA
endpoint/proxy to recover across primary failover. The application does not promote
replicas, invent secondary endpoints, or attempt writes to a read-only standby. Health
probes and request authentication share that database, so the dashboard can itself
become inaccessible during total database loss; external stdout collection is necessary
for outage observability.

Uncaught process exceptions and unhandled rejections retain graceful shutdown followed by
a nonzero exit. Compose's restart policy starts a clean process, and durable jobs
resume. Continuing an unknown corrupted execution stack is unsafe. Worker extraction
crashes are isolated and subsequent items receive fresh workers. The watchdog destroys a
task's checked-out client on cancellation; server-side statement, lock and idle-transaction
timeouts provide additional safeguards.

Neither 100% uptime nor a zero false-positive rate can be guaranteed by application code.
An operational availability target requires redundant instances, independent monitoring,
load-balancer readiness, an HA PostgreSQL service, capacity testing, and tested recovery
procedures. This work does not certify a throughput or accuracy SLA.

## Deployment and storage

1. Build using `npm run lint && npm run build`.
2. Review the protected-table contract and index-build window.
3. Run the existing migration entry point with the migration role. Schema version 14 is required. The runtime grant list now includes the new tables.
4. Provide the existing base64 32-byte `ENCRYPTION_KEY`, a writable HA `DATABASE_URL`,
and persistent `CORRELATION_DLQ_DIRECTORY` storage. Index builds run concurrently after
the schema transaction, so they no longer need a write-quiet maintenance window — but
they do need enough statement budget to finish, and they hold a lock on
`vendor_product_aliases` only briefly. Compose mounts the named `correlation-deadletters`
volume, whose directory is initialized for the unprivileged Node user.
5. Start at a conservative concurrency and measure workload-specific latency and pool wait times.

The default development spool is `/tmp/vulnstream-correlation-dlq`; use a persistent path
outside disposable development. At most 256 spool files are admitted, with each original
payload limited to 256 KiB (approximately 90 MiB maximum ciphertext storage). A full or
unwritable spool fails closed and retains durable pending work. Dead letters are
automatically flushed into `correlation_dead_letters`; correcting/replaying rejected data
remains an operator action. Preserve encryption keys for retained ciphertext.

The UI exposes:

- `GET /api/correlation`: instance-local metrics, last 300 log entries, latest 100 durable matches.
- `POST /api/correlation/concurrency`: OPERATOR/ADMIN, integer `limit` from 1 through 32.
- `POST /api/correlation/ingest`: OPERATOR/ADMIN, JSON `{ "ndjson": "..." }`, max 512 KiB string and 128 frames; returns durable acceptance.
- `POST /api/correlation/fault`: ADMIN, `{ "fault": "memory" }` or `database`; requires `FAULT_SIMULATION_ENABLED=true` and is refused outright when `NODE_ENV=production`. Simulates control-plane signals for five seconds without exhausting real memory or severing real sockets. The circuit breaker and the simulation window are persisted on `correlation_policy`, so a restart honours an open breaker instead of clearing it and a sibling replica reports the same state; simulated outages are counted separately and can never open the real breaker.
- `GET /api/correlation/search?q=...`: bounded native TSV fallback search.

The existing `/api/correlation/simulate` asset/CVE simulator is preserved. Mutation routes
inherit origin, JSON, session, CSRF, and shared rate-limit checks.

Stdout telemetry permits UUID tracking IDs and numeric metrics; raw payloads, URLs,
credentials, database error strings and stack traces are excluded. The viewer ring and
stdout queue are bounded. Admission pauses on stdout congestion; if more than 512 events
accumulate despite admission control, excess events are counted in `droppedLogs` and
surfaced in the dashboard. Use a reliable log collector. Throughput, latency, active
worker, and dead-letter capture counters are per-process lifetime; the database
match/review/dead-letter tables are durable. The separate native retention policy defaults
to 720 hours and runs bounded batches of 500 rows per relation. It removes resolved
low-confidence buffers, resolved encrypted dead letters and expired matches whose outbox
work is terminal. Open reviews, unresolved dead letters, queued/reviewing/sending
notifications, native inventory, protected articles and alias tables are preserved. Audit
and idempotency decision metadata remain durable.

## Verification

- Strict TypeScript compilation and client/server production builds.
- Full Node suite against PostgreSQL in isolated schemas: 261 tests passed with zero failures or skipped tests, including the restricted-runtime-role regression.
- Native correlation coverage includes parallel duplicate races, transaction rollback/retry, exact identifiers, conservative versions/backports, explicit exclusion precedence, early intelligence review routing, encrypted dead letters, Unicode chunk framing, concurrent-stream admission, and preservation of existing inventory columns and rows.
- Disposable browser fixture `tests/fixtures/correlationPreview.ts` supports visual verification without touching application data. It requires `TEST_DATABASE_URL`, creates a unique temporary schema, and removes it on SIGTERM/SIGINT. Its test-only login is `preview` / `Disposable-preview-password-2026!`.


## Operational completion

- `server/migrations/013_correlation_operations.sql` adds an isolated inventory projection, a read-only combined inventory view, revision evidence, review/dead-letter decisions, persistent notification deduplication and policy storage. It never alters the three protected table definitions.
- `server/correlation/inventory.ts` connects save, import, toggle and delete commands in the same transaction, preserves every CPE/PURL identity, and bootstraps pre-existing records using keyset batches. Disabled/deleted projected assets disappear from matching; owner-managed native rows remain unchanged.
- `server/correlation/operations.ts` implements audited low-confidence approval/dismissal, corrected or original encrypted dead-letter replay, conflict detection, policy changes and bounded retention. An approval requires a specific active asset and a decision note. Negated applicability language is quarantined for review.
- `server/correlation/notifications.ts` and `notificationEvidence.ts` connect native evidence to the existing outbox without inventing a CVE or severity. Target enumeration is capped at 1,000 recipients and 1,000 webhooks, and at most 20 articles are considered per sweep. Materially changed verified evidence has a new delivery revision. Existing queued evidence must remain valid at delivery time.
- `src/components/CorrelationOperations.tsx` provides native/monitored inventory search, low-confidence decision context, dead-letter correction/replay, and administrator policy/retention controls. MEDIUM email approval remains in the existing Email Queue.
- `GET /api/correlation/workflows` returns bounded review/dead-letter lists and counts. `GET /api/correlation/assets` supports bounded inventory search and UUID cursor pagination. `PATCH /api/correlation/policy` and `POST /api/correlation/retention/run` are ADMIN-only. Review decisions accept ADMIN/OPERATOR; decrypted dead-letter replay accepts ADMIN only. All mutations inherit session, CSRF, origin and shared rate limits.
- `/metrics` is independent of database authentication and requires `Authorization: Bearer` with the dedicated `METRICS_TOKEN`. Empty configuration disables the endpoint. Metrics contain numeric process/pool counters and fixed state labels, without advisory text, inventory identity or credentials. The local token is stored privately in the ignored `.runtime/metrics.token`, and local dead letters use the ignored persistent `.runtime/correlation-deadletters` directory. Neither enters Docker build context.
- `server/runtimePrivileges.ts` centralizes restricted runtime grants, including the shared rate-limit bucket permission that was previously missing. Runtime code can read owner assets and aliases but cannot rewrite them.

## Availability and alerting

"Always on, and alert when it is not" requires four independent things, because any one of them alone has a blind spot:

1. **Restart.** Compose uses a restart policy; Kubernetes uses the liveness probe. Neither can restart an instance whose event loop has wedged but whose socket still accepts connections. `HANG_DETECTION_ENABLED=true` makes `/live` answer 503 when the loop has been blocked for more than 10s, so the orchestrator replaces the instance. Liveness is configured with a 40s window (4 x 10s) to leave room for a legitimate GC pause.
2. **Correct readiness.** `/ready` previously ran `SELECT 1` and returned 200 during every pipeline outage. It now fails (503) when the supervisor is in `RECOVERING_DB_SEVERANCE` — an open breaker or a lost database — so a load balancer stops routing work at an instance that is admitting nothing. `DEGRADED_BACKPRESSURE` is reported as a warning but still returns 200, because shedding is degraded service, not a stopped one.
3. **Alerts that are actually delivered.** `prometheus.yml` had no `alerting:` block. Prometheus has no default receiver, so every rule in `vulnstream-alerts.yml` was evaluated and **discarded** — the rules existed, nothing ever reached a human. `deploy/monitoring/alertmanager.yml` supplies the route and receivers, and `repeat_interval` re-notifies for as long as the condition persists.
4. **A dead-man's switch.** All of the above is invisible in a *total* outage: with VulnStream, PostgreSQL and the collector all gone, no rule evaluates and no alert fires. `server/correlation/heartbeat.ts` POSTs to an external receiver every `HEARTBEAT_INTERVAL_SECONDS`, and the receiver alarms when the pings **stop**. Pings are suppressed while the pipeline is unhealthy, because pinging "alive" through an outage would make the switch lie. `scripts/watchdog.mjs` is the equivalent out-of-band check for deployments with no Prometheus, intended to run from cron on a different host.

**Limit, stated plainly:** no application code can guarantee 100% uptime. This work makes every failure mode observable and recoverable, and makes the *absence of the platform itself* observable for the first time. Meeting an availability target still needs redundant nodes, an HA PostgreSQL endpoint, an external receiver, and the deployment work in `deploy/kubernetes/README.md`.

`HEARTBEAT_URL` is a credential: anyone who holds it can silence the alarm by pinging it. It must be HTTPS in production, must not embed userinfo, and must never be logged.

## Load and recovery evidence

Run `npm run correlation:preflight` for a read-only protected-schema compatibility report. Run `npm run db:migrate` with migration-owner credentials for serialized migrations and inventory projection bootstrap. Run `npm run correlation:benchmark` for a disposable, streaming benchmark; optional `CORRELATION_BENCH_ITEMS`, `CORRELATION_BENCH_CONCURRENCY`, and `CORRELATION_BENCH_REPORT` control its bounded workload and report file.

The recorded local 500-item run used four workers, processed 450 unique articles and rejected 50 duplicates with zero dead letters. It measured about 50.6 items/second, p95 item latency of 125.7 ms, p99 of 150.0 ms and peak RSS of 176.1 MiB while other tests were also running. These figures describe a short synthetic workload on this host, not sustained capacity, a full-body RSS corpus, or a production latency/accuracy SLA. `correlation-benchmark-report.json` contains the exact measurements and checks.

`tests/correlation-operations.test.ts` terminates only its own PostgreSQL backend session and verifies transaction rollback and retry on a new socket. `tests/correlation-recovery.test.ts` uses an isolated TCP proxy to sever real database sockets, verifies paused admission and database-independent metrics, restores connectivity and confirms successful ingestion. Neither test restarts or disrupts the shared database server. Keyword/negation/version fixtures test conservative routing; real-world precision/recall still requires a labeled operational corpus.

`deploy/kubernetes/ha.yaml` supplies two instances on distinct nodes, independent retained spool volumes, process probes, and a disruption budget. `deploy/monitoring` supplies authenticated Prometheus scraping and alert rules. The cluster, writable HA PostgreSQL endpoint, ingress, persistent storage and external alert/log destinations must be supplied by the deployment environment. No Kubernetes client/context or external HA endpoint was available here, so cross-node rollout and database-primary promotion have not been performed. See `deploy/kubernetes/README.md` for the exact secret and deployment contract.

Final verification: strict compilation, client/server builds and 261 tests passed with no skipped cases. The production image was built locally as `vulnstream-enterprise:local-verified`. Browser checks verified an audited review approval, inventory selection and corrected dead-letter replay; `correlation-operations-verification.png` records the resulting UI. No external notifications were sent.

## Local deployment verification (October 25, 2026)

The existing Docker deployment was upgraded from schema 4 to 14 after retaining an encrypted PostgreSQL backup and the previous application image under the private, ignored `.runtime` directory. Two app replicas now run with a 512 MiB memory limit and one CPU each. Caddy resolves replica addresses dynamically and retries GET/HEAD requests against healthy upstreams. Its default TLS server name supports the configured IP-address origin without disabling certificate verification ([Caddy reference](https://caddyserver.com/docs/caddyfile/options#default-sni)).

Migration 014 adds shared concurrency policy only to the application-owned policy table. Operator changes persist in PostgreSQL and propagate on supervisor heartbeats; throughput, memory and log metrics remain per instance. Concurrent encrypted-spool flushing tolerates another replica completing the same file first.

The optional Compose `observability` profile runs Prometheus with authenticated discovery of both replicas. Its UI binds only to `127.0.0.1:9091` (override `PROMETHEUS_PORT`). The running deployment has its bearer credential mounted from `.runtime/metrics.token`; the parent directory is mode 0700. Fresh deployments must populate this file with the same `METRICS_TOKEN` configured for the app before starting the observability profile. Never commit either credential.

`npm run deployment:verify` checks the configured HTTPS origin, both container health states and both monitored instances. Use the deployed HTTPS `APP_ORIGIN` when the developer environment instead uses an HTTP origin. The explicit `--exercise` option stops only the second verified app container, checks ten proxy requests and restores that replica in a finally block. Certificate validation uses system roots plus the deployment's local Caddy CA where present. Results are recorded in `correlation-proxy-failover-report.json`.

This verifies application-replica recovery on one host. The host, proxy and bundled PostgreSQL instance remain single points of failure. Cross-node availability and actual PostgreSQL primary promotion still require the external infrastructure described above.

Final recovery check: 11 verified HTTPS proxy requests, zero failures, maximum observed latency 2,306 ms during replica loss; the second replica was restored and both monitoring targets returned healthy. The complete final database-backed Node suite passed 261 tests with zero skipped cases. Strict compilation and both production builds passed.
