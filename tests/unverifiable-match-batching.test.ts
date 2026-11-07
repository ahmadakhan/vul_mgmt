import { test } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { randomBytes, randomUUID } from 'node:crypto';
import { createPool, migrate, put, get, getMany } from '../server/db.ts';
import {
  deliverNext,
  queueConsolidatedFindingNotifications,
  queueZeroDayDigestNotification,
  type ZeroDayDigestPayload,
} from '../server/delivery.ts';
import { claimItems, claimsForJob, markClaimsDelivered, releaseClaims, releaseUnattachedClaims } from '../server/deliveryClaims.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { loadConfig } from '../server/config.ts';
import type { Requester } from '../server/network.ts';
import type { Finding, EmailRecipient } from '../src/types/index.ts';
import { settingsSchema } from '../server/validation.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import type { AppSettings, WatchListItem } from '../src/types/index.ts';

interface OutboxRow {
  id: string;
  dedupe_key: string;
  advisory_id: string;
  payload: Record<string, unknown>;
}

const url = process.env.TEST_DATABASE_URL ?? '';
async function withDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T | null> {
  if (!url) return null;
  const master = createPool(url);
  const schema = `unverifiable_${randomBytes(10).toString('hex')}`;
  let pool: pg.Pool | undefined;
  try {
    await master.query(`CREATE SCHEMA ${schema}`);
    pool = new pg.Pool({ connectionString: url, options: `-c search_path=${schema}`, max: 4 });
    await migrate(pool);
    return await fn(pool);
  } finally {
    await pool?.end();
    await master.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await master.end();
  }
}

const finding = (cveId: string, id: string, assetName: string, vendor?: string, product?: string): Finding =>
  ({
    id,
    cveId,
    matchedAssetId: id,
    matchedAssetName: assetName,
    matchedAssetVendor: vendor,
    matchedAssetProduct: product,
    matchedCpe: `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`,
    matchingMethod: 'exact',
    matchingEvidence: `Evidence for ${cveId} on ${assetName} (70% confidence)`,
    confidence: 0,
    notificationStatus: 'REVIEW_REQUIRED',
    status: 'MONITORED',
    autoDispatchedAt: null,
    advisoryId: null,
    reviewNotifiedAt: null,
    cve: {
      cveId,
      title: cveId,
      description: 'desc',
      publishedDate: '2026-01-01T00:00:00Z',
      modifiedDate: '2026-01-01T00:00:00Z',
      cvss: { version: '3.1', score: 7.5, vector: 'AV:N/AC:L', severity: 'HIGH' },
      cwe: [],
      cpeMatches: [],
      epss: { score: 0, percentile: 0 },
      cisaKev: { inKev: false, dueDate: null, cveNotes: '' },
      exploitStatus: 'None',
      remediation: { play: [], nextSteps: [] },
      sourceFeeds: [],
    },
    timeline: [],
  }) as unknown as Finding;

const recipient = (id: string, email: string, group: 'SECURITY_TEAM' | 'EVERYONE'): EmailRecipient => ({
  id,
  name: email,
  email,
  role: 'admin',
  deliveryGroup: group,
  subscriptionTier: 'ALL_SEVERITIES',
  enabled: true,
  deliverySuccessRate: 1,
});

async function saveReviewFinding(pool: pg.Pool, value: Finding): Promise<Finding> {
  const asset: WatchListItem = {
    id: value.matchedAssetId, vendor: value.matchedAssetVendor || 'acme',
    product: value.matchedAssetProduct || 'widget', assetTag: value.matchedAssetName,
    version: '1.*', cpes: [], active: true, ownerGroup: 'SOC', createdAt: new Date().toISOString(),
  };
  asset.cpes = [`cpe:2.3:a:${asset.vendor}:${asset.product}:1.*:*:*:*:*:*:*:*`];
  const cve = { ...value.cve, cpeMatches: [`cpe:2.3:a:${asset.vendor}:${asset.product}:1.5:*:*:*:*:*:*:*`] };
  const policy = { ...DEFAULT_SETTINGS, ...await get<AppSettings>(pool, 'settings', 'main'), scopeHours: 0 };
  const matched = runVulnerabilityPipeline([], [cve], [asset], [], [], policy).newFindings[0];
  assert.ok(matched);
  // Keep the fixture's confidence and evidence: the pipeline derives its own
  // score, and the test asserts the limitation notice for the confidence it
  // declared.
  const result = {
    ...matched,
    id: value.id,
    confidence: value.confidence,
    matchingEvidence: value.matchingEvidence,
  };
  await put(pool, 'watchlist', asset.id, asset);
  await put(pool, 'cveData', cve.cveId, cve);
  await put(pool, 'findings', result.id, result);
  return result;
}

test('limited-confidence findings are dispatched as one consolidated email per recipient', { skip: !url }, async () => {
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS });
    const first = finding('CVE-2026-10001', 'f1', 'server-1', 'acme', 'widget');
    const findings: Finding[] = [
      first,
      { ...first },
      finding('CVE-2026-10002', 'f2', 'server-2', 'acme', 'gadget'),
      // A finding with no vendor/product still carries the declared confidence.
      { ...finding('CVE-2026-10003', 'f3', 'server-3'), confidence: 70 },
    ];
    const recipients: EmailRecipient[] = [
      recipient('r1', 'sec-1@example.com', 'SECURITY_TEAM'),
      recipient('r2', 'sec-2@example.com', 'SECURITY_TEAM'),
    ];
    for (const target of recipients) await put(pool, 'recipients', target.id, target);

    const queued = await queueConsolidatedFindingNotifications(pool, findings);
    assert.equal(queued, 2, 'one consolidated email per recipient');

    const rows = await pool.query<OutboxRow>(
      `SELECT id, dedupe_key, advisory_id, payload FROM outbox WHERE advisory_id LIKE 'FINDINGS:%' ORDER BY target_id`,
    );
    assert.equal(rows.rowCount, 2, 'exactly two consolidated jobs enqueued');
    for (const row of rows.rows) {
      const payload = row.payload as {
        subject: string;
        cveIds: string[];
        includedFindingIds: string[];
        html: string;
        findingRevisions: Record<string, string>;
        contentRevision: string;
        generatedAt: string;
      };
      assert.equal(payload.includedFindingIds.length, 3, 'each email carries all findings');
      assert.deepEqual(payload.cveIds, ['CVE-2026-10001', 'CVE-2026-10002', 'CVE-2026-10003']);
      assert.equal(Object.keys(payload.findingRevisions).length, 3, 'findingRevisions covers every finding');
      assert.ok(row.dedupe_key, 'dedupe key populated');
      assert.ok(payload.generatedAt, 'render instant pinned for the attachment');
      // The body states the confidence limitation instead of withholding the finding.
      assert.match(payload.html, /Low confidence/);
      assert.match(payload.html, /70% match confidence/);
    }

    // A re-queue of the identical batch dedupes against the existing jobs.
    assert.equal(await queueConsolidatedFindingNotifications(pool, findings), 0, 'identical batch does not re-queue');
    const after = await pool.query(`SELECT count(*)::int AS n FROM outbox WHERE advisory_id LIKE 'FINDINGS:%'`);
    assert.equal(after.rows[0].n, 2, 'no additional jobs after re-queue');
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('a finding already announced is never included in a second email', { skip: !url }, async () => {
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS });
    const target = recipient('r1', 'sec@example.invalid', 'SECURITY_TEAM');
    await put(pool, 'recipients', target.id, target);
    const first = finding('CVE-2026-11001', 'f1', 'server-1', 'acme', 'widget');
    assert.equal(await queueConsolidatedFindingNotifications(pool, [first]), 1);
    // The pipeline stamps reviewNotifiedAt on transport acceptance; simulate the
    // stamp a later run would observe. The per-recipient claim is what actually
    // suppresses the finding (AUD-001); the stamp is aggregate reporting only.
    await put(pool, 'findings', first.id, { ...first, reviewNotifiedAt: new Date().toISOString() });
    const second = finding('CVE-2026-11002', 'f2', 'server-2', 'acme', 'widget');
    assert.equal(await queueConsolidatedFindingNotifications(pool, [first, second]), 1);
    const rows = (await pool.query('SELECT payload FROM outbox ORDER BY created_at')).rows;
    assert.deepEqual(rows[1].payload.includedFindingIds, ['f2'], 'only the un-notified finding is included');
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('a recipient added after another was notified still receives the finding', { skip: !url }, async () => {
  // AUD-001: `reviewNotifiedAt` is a global stamp. It must not hide a finding
  // from a recipient who has never been told about it.
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS });
    const analyst = recipient('r1', 'analyst@example.invalid', 'SECURITY_TEAM');
    await put(pool, 'recipients', analyst.id, analyst);
    const entry = finding('CVE-2026-12001', 'f1', 'server-1', 'acme', 'widget');
    assert.equal(await queueConsolidatedFindingNotifications(pool, [entry]), 1);
    // The first recipient's email is accepted: the finding is stamped globally.
    await put(pool, 'findings', entry.id, { ...entry, reviewNotifiedAt: new Date().toISOString() });
    await markClaimsDelivered(pool, claimsForJob(analyst.id, 'finding', [entry.id]), { jobId: randomUUID() });

    // A new recipient is added the following day.
    const newcomer = recipient('r2', 'newcomer@example.invalid', 'SECURITY_TEAM');
    await put(pool, 'recipients', newcomer.id, newcomer);
    assert.equal(
      await queueConsolidatedFindingNotifications(pool, [entry]),
      1,
      'the new recipient receives the finding despite the global stamp',
    );
    const rows = (
      await pool.query<{ target_id: string; payload: { includedFindingIds: string[] } }>(
        "SELECT target_id, payload FROM outbox WHERE advisory_id LIKE 'FINDINGS:%' ORDER BY created_at",
      )
    ).rows;
    assert.equal(rows.length, 2);
    assert.equal(rows[1].target_id, newcomer.id);
    assert.deepEqual(rows[1].payload.includedFindingIds, [entry.id]);

    // The original recipient is not told again.
    assert.equal(await queueConsolidatedFindingNotifications(pool, [entry]), 0);
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('a concurrent run cannot queue the same finding for the same recipient', { skip: !url }, async () => {
  // AUD-002: the claim is database-enforced, so the loser of the race queues
  // nothing even though both runs read the same "not yet notified" state.
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS });
    const target = recipient('r1', 'sec@example.invalid', 'SECURITY_TEAM');
    await put(pool, 'recipients', target.id, target);
    const entry = finding('CVE-2026-13001', 'f1', 'server-1', 'acme', 'widget');
    const [first, second] = await Promise.all([
      queueConsolidatedFindingNotifications(pool, [entry]),
      queueConsolidatedFindingNotifications(pool, [entry]),
    ]);
    assert.equal(first + second, 1, 'exactly one run queues the finding');
    const rows = await pool.query("SELECT count(*)::int AS n FROM outbox WHERE advisory_id LIKE 'FINDINGS:%'");
    assert.equal(rows.rows[0].n, 1);
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('a terminally failed delivery releases its claims so the finding is re-queued', { skip: !url }, async () => {
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS });
    const target = recipient('r1', 'sec@example.invalid', 'SECURITY_TEAM');
    await put(pool, 'recipients', target.id, target);
    const entry = finding('CVE-2026-14001', 'f1', 'server-1', 'acme', 'widget');
    assert.equal(await queueConsolidatedFindingNotifications(pool, [entry]), 1);
    // Simulate the terminal failure the delivery worker records: the transport
    // provably rejected the message, so the outcome is REJECTED and the claims
    // are released by the finalize path.
    await pool.query(
      "UPDATE outbox SET status='FAILED', delivery_outcome='REJECTED', error='transport rejected'",
    );
    const FAILED_JOB_HINT = (
      await pool.query<{ id: string }>("SELECT id FROM outbox WHERE advisory_id LIKE 'FINDINGS:%' LIMIT 1")
    ).rows[0]?.id;
    await releaseClaims(pool, claimsForJob(target.id, 'finding', [entry.id]), { jobId: FAILED_JOB_HINT });
    // A later run re-queues the finding. The batch is identical, so the outbox
    // dedupe key matches the FAILED row; `enqueue` re-opens the failed job
    // because it carries no confirmed transport acceptance, and the run delivers
    // a replacement email (audit follow-up, Finding 2).
    assert.equal(
      await queueConsolidatedFindingNotifications(pool, [entry]),
      1,
      'the failed notification is re-queued as a replacement email',
    );
    const reopened = await pool.query<{ status: string }>('SELECT status FROM outbox');
    assert.equal(reopened.rows[0].status, 'QUEUED', 'the failed job is reopened, preserving its identity');
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('an UNKNOWN delivery outcome is never reopened without confirmation', { skip: !url }, async () => {
  // AUD-007: a timeout / dropped connection means the prior attempt may have
  // been accepted. The dedupe key must not release the job for a resend until
  // the provider confirms the earlier attempt was not delivered.
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS });
    const target = recipient('r1', 'sec@example.invalid', 'SECURITY_TEAM');
    await put(pool, 'recipients', target.id, target);
    const entry = finding('CVE-2026-16001', 'f1', 'server-1', 'acme', 'widget');
    assert.equal(await queueConsolidatedFindingNotifications(pool, [entry]), 1);
    // The attempt reached the transport but the outcome is ambiguous.
    await pool.query("UPDATE outbox SET status='FAILED', delivery_outcome='UNKNOWN'");
    assert.equal(
      await queueConsolidatedFindingNotifications(pool, [entry]),
      0,
      'an ambiguous transport failure is never auto-resent',
    );
    // Same for a job whose transport confirmed acceptance — a fact, never re-sent.
    await pool.query("UPDATE outbox SET status='FAILED', delivery_outcome='ACCEPTED'");
    assert.equal(
      await queueConsolidatedFindingNotifications(pool, [entry]),
      0,
      'an accepted message is never re-sent',
    );
    // The claims stay held by the failed job either way; releasing them (as the
    // finalize path does for a REJECTED outcome only) is what makes re-queuing
    // possible, and even then only for NOT_ATTEMPTED/REJECTED outcomes.
    const jobId = (
      await pool.query<{ id: string }>("SELECT id FROM outbox LIMIT 1")
    ).rows[0].id;
    await pool.query("UPDATE outbox SET status='FAILED', delivery_outcome='REJECTED'");
    await releaseClaims(pool, claimsForJob(target.id, 'finding', [entry.id]), { jobId });
    assert.equal(
      await queueConsolidatedFindingNotifications(pool, [entry]),
      1,
      'a confirmed rejection is re-queued once the finalize path released its claims',
    );
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('claim expiry follows the outbox lifecycle, not just the clock', { skip: !url }, async () => {
  const outcome = await withDatabase(async (pool) => {
    // A claim is only reclaimable when its owning outbox job is gone. A queued
    // job holds its item no matter how old the claim is (Finding 4).
    const jobId = (
      await pool.query<{ id: string }>(
        `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status)
         VALUES(gen_random_uuid(),'expiry-test','email','r1','FINDINGS:test','{}'::jsonb,'QUEUED')
         RETURNING id`,
      )
    ).rows[0].id;
    const request = claimsForJob('r1', 'finding', ['f1']);
    const first = await claimItems(pool, request, { jobId });
    assert.equal(first.granted.length, 1);
    await pool.query("UPDATE delivery_claims SET expires_at=now()-interval '1 minute'");
    assert.equal(
      (await claimItems(pool, request)).granted.length,
      0,
      'an expired claim backed by a QUEUED job is never reclaimed',
    );
    // Same for a job still SENDING.
    await pool.query("UPDATE outbox SET status='SENDING' WHERE id=$1", [jobId]);
    assert.equal(
      (await claimItems(pool, request)).granted.length,
      0,
      'an expired claim backed by a SENDING job is never reclaimed',
    );
    // A FAILED job with no confirmed transport acceptance holds the claim until
    // the finalize path releases it explicitly.
    await pool.query("UPDATE outbox SET status='FAILED', error='transport rejected' WHERE id=$1", [jobId]);
    assert.equal(
      (await claimItems(pool, request)).granted.length,
      0,
      'an expired claim backed by a FAILED job is held until it is released',
    );
    // Once the job is gone (retention) the claim is reclaimable.
    await pool.query('DELETE FROM outbox WHERE id=$1', [jobId]);
    assert.equal(
      (await claimItems(pool, request)).granted.length,
      1,
      'an expired claim with no live job is re-taken',
    );
    await markClaimsDelivered(pool, request, { jobId: randomUUID() });
    await pool.query('DELETE FROM outbox');
    assert.equal(
      (await claimItems(pool, request)).granted.length,
      0,
      'a delivered claim is permanent',
    );
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('releaseClaims only deletes the claims owned by the given job', { skip: !url }, async () => {
  const outcome = await withDatabase(async (pool) => {
    // An expired claim that another job re-took must not be deleted by the
    // stale owner's failure path (audit follow-up, Finding 5).
    const staleJob = (
      await pool.query<{ id: string }>(
        `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status)
         VALUES(gen_random_uuid(),'stale','email','r1','FINDINGS:stale','{}'::jsonb,'QUEUED') RETURNING id`,
      )
    ).rows[0].id;
    const newerJob = (
      await pool.query<{ id: string }>(
        `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status)
         VALUES(gen_random_uuid(),'newer','email','r1','FINDINGS:newer','{}'::jsonb,'QUEUED') RETURNING id`,
      )
    ).rows[0].id;
    const request = claimsForJob('r1', 'finding', ['f1']);
    assert.equal((await claimItems(pool, request, { jobId: staleJob })).granted.length, 1);
    // The stale job fails terminally and releases its claim.
    await pool.query("UPDATE outbox SET status='FAILED' WHERE id=$1", [staleJob]);
    assert.equal(await releaseClaims(pool, request, { jobId: staleJob }), 1);
    // Another job takes the item and fails; its claim then expires but the
    // finalize path has not run yet, so it is still held.
    assert.equal((await claimItems(pool, request, { jobId: newerJob })).granted.length, 1);
    await pool.query("UPDATE outbox SET status='FAILED' WHERE id=$1", [newerJob]);
    await pool.query("UPDATE delivery_claims SET expires_at=now()-interval '1 hour'");
    // The stale owner's failure path runs late and tries to delete the claim.
    assert.equal(
      await releaseClaims(pool, request, { jobId: staleJob }),
      0,
      'a stale owner cannot delete another job\'s claim',
    );
    assert.equal(
      (await pool.query("SELECT count(*)::int AS n FROM delivery_claims WHERE item_id='f1'")).rows[0].n,
      1,
      'the newer job\'s claim survives',
    );
    // The actual owner can release it.
    assert.equal(await releaseClaims(pool, request, { jobId: newerJob }), 1);
    assert.equal(
      (await pool.query("SELECT count(*)::int AS n FROM delivery_claims WHERE item_id='f1'")).rows[0].n,
      0,
    );
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('a partially contested batch still delivers the granted findings', { skip: !url }, async () => {
  // Finding 3: finding A is claimed by another email, finding B is new. The
  // batch must deliver B instead of being suppressed entirely.
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS });
    const target = recipient('r1', 'sec@example.invalid', 'SECURITY_TEAM');
    await put(pool, 'recipients', target.id, target);
    const contested = finding('CVE-2026-15001', 'fA', 'server-1', 'acme', 'widget');
    const fresh = finding('CVE-2026-15002', 'fB', 'server-2', 'acme', 'widget');
    // Another run claims finding A first.
    assert.equal(await queueConsolidatedFindingNotifications(pool, [contested]), 1);
    // This run queues a batch containing both.
    assert.equal(
      await queueConsolidatedFindingNotifications(pool, [contested, fresh]),
      1,
      'the granted finding is delivered despite the denied one',
    );
    const rows = (
      await pool.query<{ payload: { includedFindingIds: string[] } }>(
        "SELECT payload FROM outbox WHERE advisory_id LIKE 'FINDINGS:%' ORDER BY created_at",
      )
    ).rows;
    assert.deepEqual(rows[1].payload.includedFindingIds, [fresh.id], 'only the granted finding is carried');
    // The contested finding stays claimed by its original job.
    assert.equal(
      (
        await pool.query(
          "SELECT count(*)::int AS n FROM delivery_claims WHERE item_id='fA' AND state='CLAIMED'",
        )
      ).rows[0].n,
      1,
      'the denied finding\'s claim is untouched',
    );
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('review settings retain boundaries and reject invalid values', () => {
  for (const value of [-1, 101, 70.5, NaN])
    assert.equal(settingsSchema.safeParse({ ...DEFAULT_SETTINGS, reviewConfidenceThreshold: value }).success, false);
  assert.equal(settingsSchema.parse(DEFAULT_SETTINGS).reviewConfidenceThreshold, 0);
  assert.equal(settingsSchema.parse({ ...DEFAULT_SETTINGS, emailEnabled: false }).emailEnabled, false);
  assert.equal(settingsSchema.safeParse({ ...DEFAULT_SETTINGS, emailEnabled: 'false' }).success, false);
});

const digest = (overrides: Partial<ZeroDayDigestPayload> = {}): ZeroDayDigestPayload => ({
  digestId: 'DIGEST_acme_widget',
  vendor: 'acme',
  product: 'widget',
  matchIds: ['m1', 'm2'],
  matchCount: 2,
  findings: [
    {
      findingId: 'f1',
      cveId: undefined,
      assetName: 'server-1 (acme widget)',
      evidence: 'Potential zero-day: vendor and product mentioned without a CVE.',
      credibilityScore: 71,
    },
    {
      findingId: 'f2',
      cveId: 'CVE-2026-30001',
      assetName: 'server-2 (acme widget)',
      evidence: 'Article references a CVE matched to this product.',
      credibilityScore: 64,
    },
  ],
  articles: [{ id: 'a1', title: 'Acme widget flaw exploited', url: 'https://example.com/a1', sourceFeeds: ['THREAT_FEED'] }],
  ...overrides,
});

test('zero-day digests deliver one consolidated email per recipient and dedupe', { skip: !process.env.TEST_DATABASE_URL }, async () => {
  const outcome = await withDatabase(async (pool) => {
    const recipients: EmailRecipient[] = [
      recipient('r1', 'sec-1@example.com', 'SECURITY_TEAM'),
      recipient('r2', 'sec-2@example.com', 'SECURITY_TEAM'),
      recipient('r3', 'everyone@example.com', 'EVERYONE'),
    ];
    const payload = digest();
    assert.equal(await queueZeroDayDigestNotification(pool, payload, recipients), 2, 'Security team only');

    const rows = await pool.query<OutboxRow>(
      `SELECT id, dedupe_key, advisory_id, payload FROM outbox WHERE advisory_id='ZERODAY:DIGEST_acme_widget'`,
    );
    assert.equal(rows.rowCount, 2, 'one job per Security-team recipient');
    const body = rows.rows[0].payload as { subject: string; zeroDayDigest: ZeroDayDigestPayload };
    assert.match(body.subject, /ZERO-DAY DIGEST/);
    assert.match(body.subject, /acme \/ widget/);
    assert.equal(body.zeroDayDigest.findings.length, 2, 'every withheld match is named');

    assert.equal(await queueZeroDayDigestNotification(pool, digest(), recipients), 0, 'identical digest dedupes');

    const noCve = digest({ matchIds: ['m9'], digestId: 'DIGEST_acme_gadget', findings: [payload.findings[0]] });
    assert.equal(await queueZeroDayDigestNotification(pool, noCve, recipients), 2);
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('zero-day digest attaches the exact email document', { skip: !process.env.TEST_DATABASE_URL }, async () => {
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'emailConfig', 'main', {
      provider: 'SMTP',
      host: 'localhost',
      port: 25,
      fromEmail: '',
      user: '',
      password: '',
    });
    const recipients: EmailRecipient[] = [recipient('r1', 'sec-1@example.com', 'SECURITY_TEAM')];
    for (const r of recipients) await put(pool, 'recipients', r.id, r);
    assert.equal(await queueZeroDayDigestNotification(pool, digest(), recipients), 1);

    const config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url,
      APP_ORIGIN: 'http://localhost',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      WORKER_ENABLED: 'false',
    });
    const requester: Requester = async () => {
      throw new Error('No network expected');
    };
    let sent = 0;
    const delivered = await deliverNext(pool, config, requester, async () => {
      sent++;
      return `msg-${randomUUID()}`;
    });
    assert.equal(delivered, true, 'digest job is deliverable');
    assert.equal(sent, 1, 'transport called once');
    const status = await pool.query<{ status: string }>(`SELECT status FROM outbox LIMIT 1`);
    assert.equal(status.rows[0].status, 'ACCEPTED');
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('dispatched findings are stamped with reviewNotifiedAt on transport acceptance', { skip: !process.env.TEST_DATABASE_URL }, async () => {
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, timezone: 'Pacific/Honolulu' });
    await put(pool, 'emailConfig', 'main', {
      provider: 'SMTP',
      host: 'localhost',
      port: 25,
      fromEmail: '',
      user: '',
      password: '',
    });
    const recipients: EmailRecipient[] = [
      recipient('r1', 'sec-1@example.com', 'SECURITY_TEAM'),
      recipient('r2', 'sec-2@example.com', 'SECURITY_TEAM'),
    ];
    for (const r of recipients) await put(pool, 'recipients', r.id, r);
    const findings: Finding[] = [];
    for (const candidate of [
      finding('CVE-2026-20001', 'f1', 'server-1', 'acme', 'widget'),
      finding('CVE-2026-20002', 'f2', 'server-2', 'acme', 'gadget'),
    ])
      findings.push(await saveReviewFinding(pool, candidate));

    assert.equal(await queueConsolidatedFindingNotifications(pool, findings), 2, 'one email per recipient');

    const config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url,
      APP_ORIGIN: 'http://localhost',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      WORKER_ENABLED: 'false',
    });
    const requester: Requester = async () => {
      throw new Error('No network expected');
    };

    let sent = 0;
    assert.equal(
      await deliverNext(pool, config, requester, async () => {
        sent++;
        return `msg-${randomUUID()}`;
      }),
      true,
      'deliverNext processes a queued job',
    );
    assert.equal(sent, 1, 'mail sender called exactly once');

    for (const f of findings) {
      const updated = await get<Finding>(pool, 'findings', f.id);
      assert.ok(updated?.reviewNotifiedAt, `finding ${f.id} is marked as announced`);
    }
    // The durable per-recipient receipt is the claim, not the global stamp.
    // The worker picks jobs in priority order, so whichever recipient's job ran
    // first, its claims are DELIVERED and the other recipient's stay CLAIMED.
    const firstClaims = await pool.query<{ recipient_id: string; item_id: string; state: string }>(
      "SELECT recipient_id,item_id,state FROM delivery_claims WHERE kind='finding'",
    );
    assert.equal(firstClaims.rows.length, findings.length * 2, 'every finding is claimed per recipient');
    for (const recipientId of ['r1', 'r2']) {
      const own = firstClaims.rows.filter((row) => row.recipient_id === recipientId);
      assert.ok(
        own.every((row) => row.state === 'DELIVERED') || own.every((row) => row.state === 'CLAIMED'),
        `${recipientId}'s claims reflect exactly one delivered batch`,
      );
    }

    // The second recipient's job is still pending; deliver it. The findings are
    // already stamped, which keeps a later run from announcing them again.
    sent = 0;
    assert.equal(
      await deliverNext(pool, config, requester, async () => {
        sent++;
        return `msg-${randomUUID()}`;
      }),
      true,
      'second recipient job is processed',
    );
    assert.equal(sent, 1, 'mail sender called for the second recipient job');

    assert.equal(await queueConsolidatedFindingNotifications(pool, findings), 0, 'already-announced findings do not re-queue');
    const after = await pool.query(`SELECT count(*)::int AS n FROM outbox WHERE advisory_id LIKE 'FINDINGS:%'`);
    assert.equal(after.rows[0].n, 2, 'no additional outbox rows after re-queue');
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('a stale consolidated batch is rebuilt without the findings that no longer apply', { skip: !url }, async () => {
  await withDatabase(async (pool) => {
    const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: url, APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: randomBytes(32).toString('base64') });
    const request: Requester = async () => { throw new Error('No network expected'); };
    const target = recipient('r1', 'sec@example.invalid', 'SECURITY_TEAM');
    await put(pool, 'recipients', target.id, target);
    const first = await saveReviewFinding(pool, finding('CVE-2026-20011', 'f1', 'server', 'acme', 'widget'));
    const second = await saveReviewFinding(pool, finding('CVE-2026-20012', 'f2', 'server2', 'acme', 'gadget'));
    assert.equal(await queueConsolidatedFindingNotifications(pool, [first, second]), 1);

    // The first finding is resolved after queueing; the second is still valid.
    await put(pool, 'findings', first.id, { ...first, status: 'RESOLVED' });
    let sent = 0;
    await deliverNext(pool, config, request, async (job) => {
      sent++;
      const html = job.payload.html || '';
      assert.ok(!html.includes('CVE-2026-20011'), 'the rebuilt body no longer names the stale finding');
      assert.ok(html.includes('CVE-2026-20012'), 'the rebuilt body still carries the applicable finding');
      assert.deepEqual(job.payload.includedFindingIds, [second.id]);
      return 'rebuilt-once';
    });
    assert.equal(sent, 1);
    assert.equal((await pool.query('SELECT status FROM outbox')).rows[0].status, 'ACCEPTED');
  });
});

test('delivery rechecks the recipient subscription before sending', { skip: !url }, async () => {
  await withDatabase(async (pool) => {
    const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: url, APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: randomBytes(32).toString('base64') });
    const request: Requester = async () => { throw new Error('No network expected'); };
    const target = recipient('r1', 'sec@example.invalid', 'SECURITY_TEAM');
    await put(pool, 'recipients', target.id, target);
    const entry = await saveReviewFinding(pool, finding('CVE-2026-20021', 'f1', 'server', 'acme', 'widget'));
    assert.equal(await queueConsolidatedFindingNotifications(pool, [entry], { recipients: [target] }), 1);
    await put(pool, 'recipients', 'r1', { ...target, subscriptionTier: 'CISA_KEV_ONLY' });
    let sent = 0;
    await deliverNext(pool, config, request, async () => { sent++; return 'must-not-send'; });
    assert.equal(sent, 0);
    const row = (await pool.query<{ status: string; error: string }>('SELECT status, error FROM outbox')).rows[0];
    assert.equal(row.status, 'FAILED');
    assert.match(row.error, /subscription/i);
  });
});

test('the delivery-claims backfill imports retained outbox history', { skip: !url }, async () => {
  // AUD-010: previously delivered emails must become per-recipient claims, or
  // an upgrade re-notifies everything the old build had already sent. The
  // backfill is migration 039; this executes it against seeded outbox rows.
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS });
    const analyst = recipient('r1', 'analyst@example.invalid', 'SECURITY_TEAM');
    await put(pool, 'recipients', analyst.id, analyst);
    // Two accepted historical batches for the analyst, and one still-queued one.
    await pool.query(
      `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,delivery_outcome)
       VALUES(gen_random_uuid(),'hist-1','email','r1','FINDINGS:hist1',
              $1::jsonb,'ACCEPTED','ACCEPTED')`,
      [JSON.stringify({ includedFindingIds: ['f1', 'f2'] })],
    );
    await pool.query(
      `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,delivery_outcome)
       VALUES(gen_random_uuid(),'hist-2','email','r1','FINDINGS:hist2',
              $1::jsonb,'ACCEPTED','ACCEPTED')`,
      [JSON.stringify({ includedFindingIds: ['f2'] })],
    );
    await pool.query(
      `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,delivery_outcome)
       VALUES(gen_random_uuid(),'hist-3','email','r1','FINDINGS:hist3',
              $1::jsonb,'QUEUED','NOT_ATTEMPTED')`,
      [JSON.stringify({ includedFindingIds: ['f3'] })],
    );
    // A webhook job is never a finding receipt for an email recipient.
    await pool.query(
      `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,delivery_outcome)
       VALUES(gen_random_uuid(),'hist-4','webhook','hook','FINDINGS:hist4',
              $1::jsonb,'ACCEPTED','ACCEPTED')`,
      [JSON.stringify({ includedFindingIds: ['f4'] })],
    );
    // Run the backfill (the migration runner skips applied versions, so execute
    // the file directly and record the version to keep the schema consistent).
    const { readFile } = await import('node:fs/promises');
    const sql = await readFile(
      new URL('../server/migrations/039_backfill_delivery_claims.sql', import.meta.url),
      'utf8',
    );
    await pool.query(sql);

    const claims = await pool.query<{ item_id: string; state: string }>(
      "SELECT item_id,state FROM delivery_claims WHERE recipient_id='r1' AND kind='finding' ORDER BY item_id",
    );
    assert.deepEqual(
      claims.rows.map((row) => [row.item_id, row.state]),
      [
        ['f1', 'DELIVERED'],
        ['f2', 'DELIVERED'],
        ['f3', 'CLAIMED'],
      ],
      'accepted history becomes a delivered receipt; queued history stays claimed; webhooks are ignored',
    );

    // The receipts actually suppress re-delivery for the analyst...
    const f1 = finding('CVE-2026-17001', 'f1', 'server-1', 'acme', 'widget');
    const f2 = finding('CVE-2026-17002', 'f2', 'server-2', 'acme', 'widget');
    await put(pool, 'findings', 'f1', f1);
    await put(pool, 'findings', 'f2', f2);
    assert.equal(await queueConsolidatedFindingNotifications(pool, [f1]), 0);
    // ...while a NEW recipient is still eligible (the claim is per recipient).
    const newcomer = recipient('r2', 'newcomer@example.invalid', 'SECURITY_TEAM');
    await put(pool, 'recipients', newcomer.id, newcomer);
    assert.equal(
      await queueConsolidatedFindingNotifications(pool, [f1]),
      1,
      'a recipient the history does not cover still receives the finding',
    );
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('releaseUnattachedClaims frees only claims with no owning job', { skip: !url }, async () => {
  const outcome = await withDatabase(async (pool) => {
    const jobId = (
      await pool.query<{ id: string }>(
        `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status)
         VALUES(gen_random_uuid(),'unattached-test','email','r1','FINDINGS:u','{}'::jsonb,'QUEUED') RETURNING id`,
      )
    ).rows[0].id;
    const request = claimsForJob('r1', 'finding', ['f1', 'f2']);
    // f1 is owned by a real job; f2 was left behind by a rolled-back queue pass.
    assert.equal((await claimItems(pool, [request[0]], { jobId })).granted.length, 1);
    assert.equal((await claimItems(pool, [request[1]])).granted.length, 1);
    // AUD-009: ownership is mandatory — the release without a job id is a
    // compile error, and a wrong job id frees nothing.
    assert.equal(await releaseClaims(pool, request, { jobId: randomUUID() }), 0);
    assert.equal(await releaseUnattachedClaims(pool, request), 1, 'only the unattached claim is freed');
    assert.equal(
      (await pool.query("SELECT count(*)::int AS n FROM delivery_claims WHERE item_id='f1'")).rows[0].n,
      1,
      'the owned claim survives the unattached cleanup',
    );
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});
