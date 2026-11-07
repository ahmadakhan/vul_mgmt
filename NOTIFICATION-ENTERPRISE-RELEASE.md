# Consolidated notification hardening — review before deployment

Base commit: `6f13ad77d6a6b56c849b3335b855fdaa06cca80d`.

- The consolidated findings pipeline no longer excludes globally-associated or
  already-stamped findings; a recipient's durable `(recipient_id, finding_id)`
  receipt decides whether it needs to be sent. Findings that are resolved,
  false-positive, patched or demonstrably not applicable remain excluded.
- Legacy buffered digest emails acquire exactly the same per-recipient claims;
  losing an outbox dedupe collision repairs the old job ownership/receipt.
- Both findings and news select at most one record per physical email address
  and consult receipts created under matching legacy recipient IDs.
- Email includes every low-confidence finding plus explanation, including plain
  text. Partial-claim batches use the operator's compiled saved template.
- Findings HTML attachment is generated from the post-edit body byte-for-byte.
  If provider constraints prevent attaching it, the send fails visibly; it
  never silently sends unaccompanied HTML. A strict 4MB document limit remains.
- Zero-day summaries remain in records/UI; matching articles flow through the
  consolidated news queue and relevant CVE findings through the consolidated
  findings queue, avoiding an overlapping third automatic email.
- PDF preview, Chromium renderer, browser-dependent scripts/tests, Docker
  browser packages, and puppeteer-core dependency are removed. Run
  `npm install --package-lock-only --ignore-scripts` after applying to regenerate
  the lockfile and prune now-unused transitive packages.

## Validation required before production

1. Back up production PostgreSQL and stage the patch on the pinned base commit.
2. `npm install --package-lock-only --ignore-scripts && npm ci` (regenerates lock after removing puppeteer and adding the jsdom test harness).
3. `npm run lint && npm test && npm run build`.
4. Run PostgreSQL tests: `TEST_DATABASE_URL=... npm run test:ci`.
5. Review reconciliation coverage with
   `node --import tsx --env-file=.env scripts/reconcile-news-history.ts --dry-run`,
   then `--apply` after a database backup.
6. Verify SMTP and every configured provider in a staging mailbox, including
   acceptance-timeout recovery, digest-vs-consolidated concurrency, changed
   recipients, custom templates, and the 4MB attachment boundary.

## Operational limitations

There is no mathematical exactly-once guarantee at the SMTP/provider boundary:
provider acceptance can become unknown after a connection failure. Keep UNKNOWN
jobs held until provider evidence resolves the outcome; do not force resend.
Historical deliveries whose outbox/URL evidence has already been deleted by
retention cannot be reconstructed automatically. Oversized one-email batches
must be reduced or handled with an explicitly designed report workflow.
Daily digests are kept as health/reporting messages and must not repeat the
underlying findings in another alert. Intentional operator-initiated manual
resends remain a separately authorized operation.
