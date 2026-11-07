# BA Threat Intel Enterprise

Vulnerability inventory correlation and advisory delivery with a React interface, a Node.js API/worker, PostgreSQL persistence, server-side operator accounts, and Docker deployment. Runtime data starts empty. No sample telemetry or simulated delivery is used.

## Deploy

Requires Docker Compose, a public hostname pointing to the host, ports 80/443 available, and outbound access to configured feeds and SMTP. The included Caddy proxy obtains HTTPS certificates. PostgreSQL and the application are not published directly.

For a new Linux host with Docker Engine, Docker Compose v2, and Bash already installed, run `bash ./install.sh`. The installer generates protected database/encryption/metrics secrets, starts PostgreSQL and waits for migrations before starting the application, then prompts for the initial administrator password. It refuses to overwrite an existing `.env.production`.

For a LAN/Tailscale deployment, run `bash ./install-lan.sh`. It asks for the server's RFC1918 LAN and Tailscale IPv4 addresses, binds Caddy to both on ports `80` and `443`, and keeps the app/API internal on port `8080`. It creates an isolated `vulnstream-lan` Compose project/database and does not publish PostgreSQL. Open `https://<LAN-IP>` or `https://<TAILSCALE-IP>`; HTTP on port `80` redirects to HTTPS. The installer creates one private-CA certificate covering both IPs, so IP-based clients can complete TLS; install `.runtime/lan-ca.crt` on each client to avoid trust warnings, and keep `.runtime/lan-ca.key` private. The LAN project inherits `EGRESS_ALLOWED_HOSTS` from `.env.production` when present; otherwise it uses the Compose defaults.

Products, threat feeds, settings, users, findings, queues, audit events, dead letters, and ML model versions are persisted in PostgreSQL. Existing ML artifacts and dead-letter spool files on the legacy named volumes are imported into PostgreSQL on first startup in database mode; the source files are removed after the database copy succeeds. Caddy certificates/configuration and optional Prometheus metrics remain in their own infrastructure volumes.

1. Copy `.env.example` to `.env.production` and restrict it with `chmod 600 .env.production`.
2. Set `APP_HOST`, two different random hexadecimal database passwords, and a random 32-byte base64 `ENCRYPTION_KEY`. Generation commands are in the example. Retain the encryption key in your secret manager: losing it makes saved feed/webhook credentials unrecoverable.
3. Configure SMTP and add any custom SMTP, feed, or webhook hostname to `EGRESS_ALLOWED_HOSTS`. Feed/webhook endpoints must use public HTTPS on port 443; SMTP hosts use TLS or STARTTLS on the configured SMTP port. Secrets belong in credential fields, not feed URLs.
4. Run:

```sh
docker compose --env-file .env.production up -d --build
# Enter an initial administrator password without putting it in shell history:
read -r -s -p 'Administrator password: ' operator_password
printf '\n'
printf '%s' "$operator_password" | docker compose --env-file .env.production exec -T app node server-dist/create-user.js admin ADMIN
unset operator_password
```

Open `https://YOUR_APP_HOST`, sign in, add inventory and feed configuration, and run a pipeline.

Scheduling and automatic dispatch are disabled initially; enable them only after checking correlations and channel configuration. Configure recipients before enabling automatic dispatch. Additional operators can be created by an administrator in Settings. There is no default account or password.

Configure email delivery in **Settings → Email delivery**. Choose one of two methods: **SMTP** or **Email API**. SMTP can use the deployment's `SMTP_*` settings or any relay such as Gmail, Maileroo, Lettr, and Mailjet by entering its host, port, encryption, and credentials. Gmail uses `smtp.gmail.com`, your full Gmail address, and a generated 16-character App Password; port 587 uses STARTTLS, while port 465 uses implicit TLS. Custom SMTP hosts must be included in `EGRESS_ALLOWED_HOSTS`. Email API accepts an HTTPS endpoint (port 443), an authentication key, and an optional Source / Domain value; its default header is `Authorization: Bearer <key>`. Use `{domain}` in the endpoint URL to insert the Source / Domain value. The API hostname must be included in `EGRESS_ALLOWED_HOSTS`; the request body uses `from`, `to`, `subject`, `text`, optional `html`, and delivery headers. SMTP passwords and API keys are encrypted in PostgreSQL and never returned to the browser. Leaving a saved credential blank keeps it. Changes apply to subsequent outbox attempts without restarting the worker. Use **Queue test email** and check **Delivery Log** for provider acceptance. Existing vendor-specific Mailgun, Mailtrap, SendGrid, and Postmark configurations remain readable by the backend.

Self-service password resets use the deployment's `SMTP_HOST` and `SMTP_FROM` settings and the email address configured on each operator account. SMTP is required in development and production; reset codes are exposed in API responses only when `NODE_ENV=test`. Public reset endpoints share per-IP and per-account quotas across replicas and return `429` with `Retry-After` when exhausted.

The example outbound allowlist includes the existing provider API and SMTP hosts. If `EGRESS_ALLOWED_HOSTS` is explicitly set in an existing deployment, add the selected relay or custom API hostname. Provider failures use the durable retry queue and honor `Retry-After`; invalid requests and authorization failures require correction and a manual retry. API delivery, like SMTP, is at least once. Provider acceptance does not prove inbox delivery.

With **Automatic dispatch** enabled, every confirmed threat is queued for email. Enable **Combine threats into one email** to hold detections for the configured digest window and send one combined message per recipient, even when the detections arrived in different pipeline runs. Each recipient receives only the findings its subscription tier permits. Delivery is content-deduplicated: rerunning the same batch, retrying a failed attempt, or restarting the worker does not create a second message, and transient failures retry on an exponential backoff before the job is marked failed. The **Email retry policy** in **Settings → Processing** controls whether retries are enabled, the total attempt count, the initial delay, and the maximum delay (defaults: six attempts, one-minute initial delay, one-hour cap). Setting the maximum attempts to 1 keeps the first delivery but disables automatic retries; permanent provider rejections still require operator correction. Digest state is stored in PostgreSQL, so a restart does not lose buffered detections.

The migration job owns schema changes. The runtime database role has no DDL privileges and cannot update/delete audit records. Existing database volumes do not rerun initialization: changing an environment password alone does not rotate the database role password.

## Supported behavior

- MITRE CVE ingestion from the official CVE JSON 5 List, NVD API ingestion, CISA KEV and FIRST EPSS enrichment, OpenCVE API v2 CVE/CPE enrichment, VulnCheck KEV exploited-in-the-wild signals, and schema-validated normalized JSON feeds. OpenCVE and VulnCheck require provider Bearer tokens and are seeded disabled until credentials are configured. All CVE sources merge by canonical CVE ID; VulnCheck exploitation remains distinct from CISA KEV. RSS/Atom news and advisory evidence is supported, with BleepingComputer, SANS ISC and MSRC sources seeded disabled for connectivity testing before enablement. News is matched to vendor + product as review evidence, grouped by canonical CVE and asset, and cannot create automatic alerts or override structured affected-version exclusions. STIX and CSAF adapters are not implemented.
- NVD, MITRE, OpenCVE and VulnCheck KEV use committed incremental checkpoints with a 10-minute overlap; initial sync is capped at 24 hours and catch-up runs use daily slices. MITRE/OpenCVE skip unchanged revisions, and EPSS caches previously queried scores for one hour while fetching newly matching CVEs immediately. Each pipeline reconciles current inventory against all cached CVEs. Existing findings retain stable IDs and history as applicability changes.
- CPE/PURL inventory matching with version exclusions. Matching is strict-first: PURL, strict CPE, alias thesaurus, then whole-word vendor/product prose. Only the structured tiers can auto-dispatch; alias and prose matches stay review-only. Unknown versions or complex NVD applicability require review. Unsigned VEX cannot suppress findings.
- Vendor/product aliases are self-maintaining but bounded. Inventory aliases come from each asset's declared identity and its own CPEs. Correlation aliases are learned only from confirmed findings (auto-dispatched, delivered, resolved or patched) — never from an unreviewed text match. Automatic rows expire 30 days after their last supporting evidence; operators can promote a row to permanent or revoke it so the relation is never learned again.
- `npm run matching:evaluate` runs a labelled precision/recall corpus and fails on regression. The gate is part of CI and reports per evidence class plus high-confidence false positives (the only errors that could auto-dispatch).
- Durable PostgreSQL outbox with retries and recovery. SMTP acceptance and webhook HTTP acceptance are recorded as `ACCEPTED`; this is not proof of inbox delivery. Delivery is at least once. Stable email Message-ID and webhook idempotency keys support recipient-side deduplication.
- ADMIN manages accounts/configuration, OPERATOR manages inventory/findings and pipeline runs, VIEWER reads. Opaque server sessions, CSRF/origin checks, password hashing, persistent login throttling and encrypted channel secrets protect the API.
- Health reports actual database/process/worker measurements. External NTP and mail inbox delivery are not inferred.

## Develop and validate

Node.js 26+ and PostgreSQL 17 are used for validation. Set `DATABASE_URL`, `APP_ORIGIN=http://127.0.0.1:8080`, and a generated `ENCRYPTION_KEY` in the process environment; environment files are not loaded implicitly. For the built application:

```sh
npm ci
npm run lint
npm run build
npm run operator:create -- admin ADMIN # reads password from standard input
npm start
```

Development mode applies migrations automatically. Production requires the migration job. `npm run dev:server` runs the API watcher; `npm run dev` runs Vite on loopback port 3000 (set APP_ORIGIN to the Vite origin for that workflow).

```sh
npm test
TEST_DATABASE_URL=postgresql://USER:PASSWORD@HOST/TEST_DB npm run test:integration
npm audit
```

Without `TEST_DATABASE_URL`, `npm test` explicitly skips the database suite; this is not full validation. The integration command requires the variable. Tests create and remove a uniquely named schema in the supplied test database. Use a dedicated test database with schema-creation privileges. External transports are mocked; tests do not send messages to real recipients.

See [OPERATIONS.md](OPERATIONS.md) for backups, restore, monitoring and release procedures, and [AUDIT.md](AUDIT.md) for verification scope and limitations.

Operational events are available under Logs → Operational events, with category, level and full-text filters, structured context and cursor pagination. Pipeline, feed, matching, delivery, system and API failures are recorded separately from the retained hash-chain audit trail. Deployment requires migration 002; run the migration service before starting the updated production application. News evidence appears under Threat Cache → News & advisory evidence.

RSS retrieval honors the pipeline ingestion window, validates XML, accepts DTDs without resolving external DTDs or expanding declared entities, and rejects external entity declarations. Malformed or future-dated entries are quarantined. Canonical URLs remove tracking parameters; repeated reporting adds evidence to a CVE/product correlation rather than creating duplicate CVEs. Similar titles alone are not proof of vulnerability identity. News mentions are review candidates; zero false positives or negatives cannot be guaranteed. Providers may restrict automated requests; use the source connectivity test and inspect feed logs in the target deployment.
