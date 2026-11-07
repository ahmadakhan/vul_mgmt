# Operations

## Configuration and release

Keep `.env.production` out of source control and restrict host access. Protect database backups and the encryption key separately. Use a firewall to expose only 80/443 and your administrative access. Keep Docker, PostgreSQL, Caddy and Node base images patched; rebuild and test releases before rollout. The supplied image runs as a non-root user, with a read-only application filesystem, dropped capabilities and no privilege escalation. Set resource limits and monitoring to match your host and workload.

Release with `docker compose --env-file .env.production up -d --build`. Confirm the migration job exits successfully, `docker compose --env-file .env.production ps` reports healthy services, and sign-in, a pipeline and a test delivery work. Before upgrading, take a backup and test restoration. Do not run older code against a newer schema unless compatibility has been verified. Stop application traffic before a rollback requiring database restoration.

For a fresh Linux installation, `bash ./install.sh` creates a protected `.env.production`, generates distinct database passwords and encryption/metrics secrets, starts the Compose stack, and prompts for the initial administrator password. It requires Bash, Docker Engine, and the Compose v2 plugin; it does not install or modify the host's Docker packages. In database storage mode, products, feeds, settings, queue records, audit data, dead letters and ML model artifacts are stored in PostgreSQL. The ML/DLQ named volumes are retained only to import data from earlier filesystem-backed deployments; remove them after confirming migration and backups. Caddy certificate state and optional Prometheus time-series data remain in infrastructure volumes.

`bash ./install-lan.sh` is a separate LAN/tailnet option. It binds Caddy to the entered RFC1918 and Tailscale IPv4 addresses on ports `80` and `443`; HTTP redirects to HTTPS and the API remains internal on container port `8080`. It uses an isolated PostgreSQL volume/project and inherits `EGRESS_ALLOWED_HOSTS` and `EGRESS_ALLOWED_HOSTS_EXTRA` from `.env.production` when present; otherwise it uses the bundled Compose defaults. An explicit empty allowlist still denies outbound hosts. A private CA signs one certificate containing both IP addresses, which also supports clients that omit SNI for IP URLs. Install `.runtime/lan-ca.crt` in each client's trusted root store; protect `.runtime/lan-ca.key` and restrict access to the Docker host. Restrict access to a trusted network and do not port-forward this service.

For an existing LAN deployment, update `APP_ORIGIN` in `.env.lan` to `https://<TAILSCALE-IP>`, generate the combined-IP certificate, then apply the HTTPS overlay without recreating the database:

```sh
```sh
bash ./scripts/lan-tls-certs.sh
docker compose --project-name vulnstream-lan --env-file .env.lan -f compose.yaml -f compose.lan.yaml up -d --force-recreate --no-deps app proxy
cp .runtime/lan-ca.crt "$HOME/vulnstream-lan-root.crt"
```

Install `vulnstream-lan-root.crt` in each client's trusted root store. Renew the leaf certificate annually by rerunning the helper and force-recreating the proxy. The root certificate is public, but never export or distribute `.runtime/lan-ca.key`. Port `443` must also be allowed through the host firewall; HTTP redirects only work for clients that can still reach port `80`.

The runtime's `/live` endpoint reports process availability and `/ready` checks PostgreSQL. Neither certifies feed freshness or successful delivery. Monitor authenticated System Health, feed errors, execution failures, queue depth, failed deliveries, database size and worker heartbeat (normally updated every five seconds outside an active run). Alert on heartbeat staleness relative to your maximum ingestion time. Logs are JSON on standard output; retain and restrict access through your platform. Feed/provider error details may contain operational information.

The header displays total/enabled feed counts. Its "Online for" indicator is the current API process uptime, refreshed every minute via `/api/system-uptime`; it resets on API restart and is not host uptime or a historical availability guarantee. Failed uptime checks display "Uptime unavailable".

## Daily digest

The daily digest counts eligible findings created in the last 24 hours that match each recipient's subscriptions, not all open vulnerabilities. Resolved, inapplicable and held-for-review findings are excluded from the total; the review section reports held findings separately. Counts represent CVE-to-asset findings, so one CVE affecting multiple assets can count more than once. Remediation guidance reflects only severities present in that recipient's digest.

Health details are a snapshot at generation time, not live delivery-time metrics. Worker process uptime resets on restart and is not an availability percentage. Delivery counts cover retained outbox jobs across channels: queued, sending, awaiting review, provider accepted and failed; provider acceptance does not confirm inbox delivery. "Next Delivery Attempt" is the next future queued attempt, while "Next Scheduled Digest" is the next calendar day's configured send time in the workspace timezone, including daylight-saving changes.

## Operational logs

The Logs workspace separates event ownership: **Operational events** contains pipeline, feed, matching, email, issue and general event activity, and intentionally excludes `ML` and `SYSTEM`; **ML logs** contains only `ML` events; **System logs** contains only `SYSTEM` events. **Audit trail** is a separate record of audited operator actions. An event missing from one view may belong to another tab rather than being absent from retention.

Operational events can be searched across code, message and context, then narrowed by category, level or execution UUID. ML and System logs each support search and level filters. All three event views are newest-first and use cursor-based pages; automatic refresh pauses while browsing older pages. Clear filters before broadening a search.

Select an event to inspect its full message, failure details and structured context, with execution and tracking identifiers plus available timing/correlation metadata. The operational-event detail view can use a tracking ID to search related activity. Context is redacted before persistence; it is not a substitute for protected application or provider logs, and retained log access should remain restricted.

## Back up

Run from the repository directory on the Docker host. Backups are consistent PostgreSQL custom-format dumps. Restrict destination permissions and encrypt off-host copies.

```sh
umask 077
mkdir -p backups
docker compose --env-file .env.production exec -T db pg_dump -U vulnstream_migrator -d vulnstream -Fc > "backups/vulnstream-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

Check the command exit status and verify archive contents with `pg_restore --list`. Back up the protected deployment configuration and `ENCRYPTION_KEY` separately. Regularly restore to an isolated environment and verify accounts, inventory, audit history and decryption. A database dump alone cannot recover encrypted secrets without the matching key. Define backup frequency and retention from your recovery objectives.

## Restore

Restore into a fresh, isolated Compose project first. Initialize its database with the same database/role names and new protected database passwords. Keep `app` and `proxy` stopped. For example, with the intended project's environment and dump paths:

```sh
docker compose --env-file .env.production stop app proxy
docker compose --env-file .env.production up -d db
# This replaces data in the selected database. Confirm the target before running.
docker compose --env-file .env.production exec -T db pg_restore -U vulnstream_migrator -d vulnstream --clean --if-exists --exit-on-error < backups/SELECTED.dump
docker compose --env-file .env.production run --rm migrate
docker compose --env-file .env.production up -d app proxy
```

Use the encryption key corresponding to the backup. Restore tests must have external SMTP/webhook/feed egress blocked: restored pending jobs can resume. In a real recovery, reconcile provider receipts before restarting delivery to avoid duplicate messages. Sessions in the backup can be invalidated by an administrator running `DELETE FROM sessions` using the database owner role.

## Credentials and delivery

Rotate database passwords using PostgreSQL role administration and update the protected environment together. Re-enter feed/webhook credentials to rotate them. For encryption-key rotation, set the new write key in `ENCRYPTION_KEY` and keep required retired keys in `ENCRYPTION_KEYS` (up to 16 comma-separated base64 32-byte keys). The current key is always tried first for new writes, and existing authenticated ciphertext can be read with retained keys, including legacy envelopes and correlation dead letters. Changing the write key does not automatically re-encrypt old records or backups: keep required keys until protected data and backups have been migrated. Schedule a controlled rotation with delivery/scheduling disabled and verify decryption before resuming. Never discard the old key until backups no longer require it.

SMTP uses TLS (implicit on 465, required STARTTLS otherwise), certificate validation and bounded timeouts. Generic webhooks carry `X-BA-Threat-Intel-Signature`, `X-BA-Threat-Intel-Timestamp` and `Idempotency-Key`; verify the HMAC over `timestamp + '.' + exact body` and reject stale timestamps at the receiver. Check the source for exact header casing (HTTP headers are case-insensitive). Slack/Teams payloads use their supported text format.

Jobs retry transient failures up to six attempts with backoff; permanent 4xx responses except 408/429 fail immediately. Failed jobs can be explicitly retried. A crash after remote acceptance and before local commit can duplicate a delivery, even with durable storage. Do not describe `ACCEPTED` as delivered/read. Use provider telemetry for those claims.

Retries require evidence that a previous submission was not accepted. SMTP connection/authentication/envelope failures are safe to retry; a lost connection after DATA can hide acceptance and is held for confirmation or explicit operator recovery. A custom HTTP relay without a lookup endpoint is not presumed safe merely because it has no configured source domain. Password-reset delivery uses the selected workspace provider, respects the master email switch, skips advisory attachments, and stores only reset-code hashes rather than queueing raw codes.

The self-healing watchdog claims alert admission atomically with per-recipient durable jobs. A failed queue transaction does not consume the alert cooldown; new incidents and re-enabled email can notify again without duplicating recovery runs. Disabled feeds and an explicitly disabled scheduler remain disabled. Memory alarms use V8/process limits rather than the allocated heap size. The watchdog reads active/recent execution state, not the full retained history.

Shared dead-letter spools use renewable filesystem leases for each letter before replay. Validate atomic directory creation and modification-time behavior on the target shared filesystem. A failed replay preserves the encrypted letter, database inserts remain idempotent, and retained decryption keys must be available to every replica.

The authenticated email-preview sink uses DOMPurify and restricted presentation styles. Script/event/form/SVG injection, encoded executable links, external image tracking and overlay CSS are blocked; safe email tables, text, inline presentation and embedded raster images remain supported. Mail-client rendering and provider acceptance still require target-environment acceptance tests.

The read-only Compose application uses separate writable volumes for dead letters and ML models. Preserve both in backup/restore procedures. The model path is `/var/lib/vulnstream/ml`; the image creates it with runtime-user ownership. The latest audit host had no Docker CLI, so image startup, volume ownership on an existing deployment, restore drills and shared-filesystem behavior must be verified before rollout.

### ML readiness and training

Authenticated `GET /api/ml/status` lists all 18 models, loaded versions, minimum sample counts and the latest scheduled training result. `UNTRAINED` means the deterministic fallback is active, not that learning has completed. Never bypass quality gates or generate fictitious analyst outcomes to make this count green.

With `WORKER_ENABLED=true`, training runs hourly by default (`ML_TRAINING_INTERVAL_MS`), uses `ML_LOOKBACK_DAYS`, signs artifacts when `ML_SIGNING_KEY` is configured, and refreshes the in-process runtime after saving qualified models. Each cycle has a distinct artifact version so rollback history is retained. The standalone command is `node --import tsx --env-file=.env server/ml/train/cron.ts`; supply a valid `DATABASE_URL` and the same model directory/signing key as the API. Restart an API after externally running standalone training to load its artifacts.

Real correlation telemetry is sampled once per minute; finalized email attempts record observed retry intervals and outcomes. Reviewed findings train applicability/ranking models. Labels not implied by those records (calibration, exploit-risk assessment, severity assessment, recipient digest relevance, zero-day cap outcomes and composition preferences) are accepted via **ADMIN/OPERATOR-only**, CSRF-protected `POST /api/ml/feedback`. Submit one analyst-verified sample at a time; validation rejects unknown fields, nonfinite/out-of-range features, unsupported labels, oversized payloads and mismatched zero-day outcome counts. For example:

```json
{"source":"calibrationPairs","sample":{"credibilityScore":75,"isActionable":true}}
```

The other supported `source` values are `exploitRiskSamples`, `severityTierSamples`, `digestSelectionSamples`, `zeroDayRateLimitSamples` and `emailCompositionSamples`; their exact feature/label contracts are defined in [the feedback schema](server/ml/feedback.ts). These events are training data: retain ML operational events for at least the training lookback.

Finding `mlAssessment` and calibrated news scores are recommendations only: they cannot upgrade confidence, undo VEX, suppress authoritative applicability, or bypass dispatch policy. Digest relevance ranks already-subscribed findings without dropping them. Learned zero-day caps cannot exceed the existing maximum; overflow remains in durable digests. Learned delivery delays cannot shorten the configured retry backoff or a provider's `Retry-After`, and classifier recommendations cannot override transport rejection evidence.

## Capacity and audit boundaries

New audit entries carry optional hash-protected context: action code, resource type/identifier, explicit outcome, optional request reference and supplied field names. Supplied fields are not a before/after diff, and values are not copied from command payloads. Unknown outcomes display as recorded rather than success. Account creation records the authenticated administrator as actor; bootstrap provisioning records a system actor. Audit text is bounded, control characters are normalized, and common credential forms are redacted before hashing. Restrict audit/export access because actor names, source IPs and legitimate operational details remain sensitive.

Historical audit hashes remain unchanged. Context-aware writers/verifiers must be deployed together: older verifiers do not understand context-bearing hashes. The UI displays a timestamped retained-chain check, its checked entry count and an accessible Merkle fingerprint; later appends are not covered by that snapshot. External immutable anchoring is not checked. CSV/JSON exports honor active filters and retain structured context. Verify exported history with the matching hash implementation and a trusted external anchor when administrator-level tamper detection is required.

Schema version 36 maintains exact collection counts and dashboard KPIs in `state_metrics` using transactional statement triggers. Apply `npm run db:migrate` with the migration-owner connection before starting this release; deployments with a separate application role must also run the migration job with `GRANT_RUNTIME_ROLE=true`. The first backfill scans existing records while holding a write-blocking table lock, so schedule it in a maintenance window and allow the migration to finish before admitting application traffic. Do not edit counters directly; owner-initiated repairs can rerun migration 036 transactionally to rebuild them from records.

Audit verification uses a repeatable-read snapshot and bounded cursor batches, with a compatible sorted Merkle root. Memory use is bounded, but verification still reads the full retained chain and can be I/O-intensive. Disconnected requests and verification deadlines cancel the transaction.

`EGRESS_ALLOWED_HOSTS` replaces the bundled host list when explicitly configured, including an empty value to deny all outbound hosts. Omit it to use the defaults, or use `EGRESS_ALLOWED_HOSTS_EXTRA` for additions to the selected list. Include all feed, redirect and email-provider hosts needed by the deployment when supplying a restricted list.

Recommended-feed catalog changes do not register missing feeds when `BOOTSTRAP_RECOMMENDED_FEEDS=false`. To import missing catalog entries, set it to `true` and restart the API; existing IDs and equivalent source URLs are skipped. Restore it to `false` afterward if deletions should remain deleted. Existing operator settings are preserved except for known-unavailable, unchanged vendor-seeded endpoints: X/Twitter's obsolete security feed stays disabled with an explanatory error. Its redirect host `blog.x.com` is allowlisted, but allowing the host does not make the publisher's blocked feed usable.

Advisory PDFs are printed from the final email HTML using headless Chromium so that the attachment preserves the email's layout, styling, and links. The renderer disables JavaScript, blocks network requests, and removes active content before printing. The Docker runtime and test images install Chromium; outside Docker, install Chromium or Chrome and set `PUPPETEER_EXECUTABLE_PATH` or `CHROME_EXECUTABLE_PATH` to its executable. PDF rendering failures are logged and delivery continues as HTML-only. Set `ATTACH_ADVISORY_PDF=false` to disable attachments.

`npm run test:unit` and `npm run test:unit:watch` use the repository's `node:test` suite. `npm run test:ci` requires `TEST_DATABASE_URL` and runs the same suite with database tests enabled; use a disposable test database, not the live application database. The legacy `test:vitest` alias invokes the supported unit runner.

This release uses a complete inventory/CVE snapshot for correlation and the UI, and serializes state-changing transactions. It is intended for a bounded organizational inventory; it has not been load-tested for a full historical NVD mirror or high concurrent operator counts. Measure representative ingestion, memory, response size and transaction latency before setting deployment capacity. NVD uses bounded daily incremental windows with a 50,000-result cap, EPSS queries only inventory-related CVEs, and response limits vary by adapter (8 MiB by default). Oversized feeds fail explicitly. Choose an appropriate ingestion window; do not silently assume a partial scan is complete.

The UI retains the latest 500 audit entries while the database retains the full chain. Application-role audit writes are append-only; a database owner can still alter schema/data or truncate history. Export audit records to independently controlled immutable storage if tamper evidence against administrators is required. No automated business-record retention/deletion policy is enabled; monitor storage and define an approved archival policy.

Matching does not implement every vendor version convention or full NIST applicability logic. Review flagged matches and vendor advisories. Live provider compatibility, public TLS issuance, restore objectives, accessibility and deployment load require acceptance testing in the target environment.

Registering a product with CPE version `*` intentionally covers all versions and can initiate automatic dispatch under the configured confidence threshold. Partial version patterns, unknown concrete-version ordering, unresolved identities/platforms and review-only source evidence retain their review gates. A new or changed registered product is matched against the complete cached vulnerability corpus once; normal discovery remains scoped to the run window. Existing findings are revalidated independently of age so an unchanged, still-affected product does not become inapplicable solely because a CVE leaves the window. Inventory fingerprints commit atomically with the matching results.

## Matching quality and alias governance

Finding Dispatch settings expose independent queued-email and review-email confidence minimums (inclusive 0-100). The saved queued minimum is authoritative even when ML is trained. Review notices require the review toggle and review minimum; lower-confidence findings remain available for operators without automatic review email. Version-uncertain matches keep their measured scores and can use the queued minimum only when the explicit dispatch override is enabled. Hard source/applicability/contradictory-identifier holds are not released by lowering a number. The master email switch still controls all transport.

Review emails are filtered by each Security-team recipient's subscription and revalidated against current policy, inventory and CVE evidence before sending. Overlapping batches reserve each finding once per recipient. CVEs link to HTTPS source guidance with NVD fallback. A policy-blocked review can resume after renewed eligibility, while transport failures retain their normal retry/operator-recovery rules. Previously queued legacy review content without revision evidence is held; rerun correlation for a refreshed notice.

Run `npm run matching:evaluate` (also enforced in CI) to measure precision and recall on the labelled corpus in `tests/fixtures/matching-corpus.ts`. The report is broken down by evidence class and flags any expected-negative case that reaches the 90% auto-dispatch threshold. Adding a production mismatch to that corpus is the required regression step; the corpus currently covers 30 labelled cases and is a curated gate, not a statistical estimate over a full historical CVE mirror.

Alias behavior is deliberately conservative:

- Inventory aliases are derived from active assets and their own CPE identities, so they reconcile when the asset is renamed or removed.
- Correlation aliases are learned only from confirmed findings. Review-only fallback matches are not evidence.
- Automatic rows expire after 30 days without fresh support, then are deleted. Promote a row to make it a permanent operator alias; the automatic lifecycle will not modify or expire it.
- Revoke a row to create a tombstone. Revoked relations are not used for matching and are not re-learned; delete the tombstone to allow learning again.
- Text fallback requires whole identity words and ignores identities made only of words shorter than three characters (`os`, `ai`, `go`). Those products need CPE, PURL or explicit alias evidence.

### Feed timeout recovery

Threat Sources supports a request timeout (5–120 seconds) and recovery delay (1–60 minutes) per source. Existing sources retain adapter timeout defaults until configured. Failed ingestion schedules recovery after five minutes by default, doubling after repeated failures up to one hour. Automatic scheduled, catch-up, and recovery runs are opt-in through **Enable server scheduler**, which defaults off so starting the stack does not launch ingestion. Manual pipeline runs remain available. Successful ingestion clears the failure counter and retry deadline; disabling a source prevents automatic recovery. Retry deadlines appear beside failed sources and persist across server restarts. Automatic recovery requires both the scheduler and `WORKER_ENABLED=true` and can wait for an active pipeline to finish.

Feed ingestion has a total per-source budget controlled by `FEED_MAX_DURATION_SECONDS` (default 1800; range 1–7200). It includes pagination and retry waits; individual requests are capped to the remaining budget. A source exceeding this budget discards its incomplete response and enters automatic recovery. Empty EPSS scopes clear expired retry state without claiming verified connectivity. Loss of the worker lock connection prevents further source requests and commits. Ingestion phases report warnings when sources return partial parsing warnings.

### MITRE CVE source

The enabled `MITRE CVE — Official CVE List` source is added once on upgrade and on fresh deployments. It reads the official CVE Program repository at `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json`, then fetches CVE JSON 5 records by validated CVE ID. No API key is required. Add `raw.githubusercontent.com` to any custom `EGRESS_ALLOWED_HOSTS`; the bundled defaults already include it. Restart the server to run the source bootstrap. Operator changes and later deletions are preserved.

The adapter filters the rolling change log by its committed checkpoint, skips revisions already imported, and caps a run at 5,000 unique changed records. It uses the index ETag to avoid transferring an unchanged log. A changed log is still fetched as metadata because the provider does not expose an arbitrary since-checkpoint endpoint. Record requests run with at most three concurrent transfers, with all starts paced by the configured source rate. Checkpoints older than available delta history fail explicitly instead of silently skipping the missing period. Source request timeouts and the overall feed duration budget still apply. The log permits a 64 MiB response, and individual records permit 4 MiB.

Published records participate in the existing correlation engine; rejected records participate in withdrawal handling. CVE JSON version rules may contain exceptions or custom version schemes, so MITRE matches require applicability review and cannot initiate automatic dispatch on their own. CPEs, CNA product descriptions, CVSS metrics, CWE IDs and advisory references are retained. Canonical CVE-ID merging combines source attribution across MITRE, NVD and other feeds, while the existing CVE-and-asset finding identity prevents repeated findings across runs. Newer source revisions retain the existing revision-selection behavior.

### Incremental ingestion and caching

NVD, OpenCVE, MITRE and VulnCheck KEV maintain internal `feedCursors` records, bound to the source URL, adapter and credentials. Checkpoints, imported intelligence, findings and delivery jobs commit together. Failed, cancelled or obsolete-source runs do not advance a checkpoint. Credentials or endpoint changes invalidate the old checkpoint automatically. Existing installations bootstrap safely rather than trusting legacy `lastSync` timestamps as data-completeness checkpoints.

The initial sync fetches at most the selected lookback or 24 hours, whichever is smaller. Subsequent syncs resume from the committed watermark with a 10-minute overlap for delayed updates; they do not re-fetch the full selected lookback. A long outage is caught up in daily slices when the scheduler is enabled. Circuit cooldowns still apply. Broad scope selection does not request a full historical reimport; historical coverage requires a separate historical source/import. Correlation still evaluates all cached CVEs against current inventory on every run.

OpenCVE and MITRE retain recent per-CVE revision timestamps to avoid fetching unchanged detail documents in the overlap. MITRE advances only through the published log watermark and installs its ETag only after consuming that index completely. EPSS scores are cached for one hour per source and queried CVE set; newly matching CVEs are fetched immediately, and an expired cache refreshes all current candidates without extending old scores indefinitely. CISA KEV and RSS/JSON sources continue to use conditional requests where the provider supplies an ETag. VulnCheck KEV uses the documented last-modified date filters with 100-record pages and durable checkpoints. Catalog-only providers still require complete authoritative snapshots when changed; skipping portions could miss withdrawals or removals. Provider rate limits and initial-sync costs still apply.

RSS/Atom downloads and parsing share a 16 MiB limit and a 10,000-entry ceiling so large vendor archives (including MSRC) can be filtered to the selected time scope. DTDs are accepted without resolving external DTDs or expanding declared entities; external entity declarations remain unsupported. Interrupted HTTP responses (including connection resets and aborted transfers) receive bounded retries in the provider adapters. A provider HTTP 401 requires checking its token and access; an undecryptable stored secret requires re-entry or restoration of the original encryption key.
