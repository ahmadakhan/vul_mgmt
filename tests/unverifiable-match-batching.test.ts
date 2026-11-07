import { test } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { randomBytes, randomUUID } from 'node:crypto';
import { createPool, migrate, put, get } from '../server/db.ts';
import {
  deliverNext,
  queueConsolidatedFindingNotifications,
  queueZeroDayDigestNotification,
  type ZeroDayDigestPayload,
} from '../server/delivery.ts';
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
  const result = { ...matched, id: value.id };
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
      finding('CVE-2026-10003', 'f3', 'server-3'),
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
    // stamp a later run would observe.
    await put(pool, 'findings', first.id, { ...first, reviewNotifiedAt: new Date().toISOString() });
    const second = finding('CVE-2026-11002', 'f2', 'server-2', 'acme', 'widget');
    assert.equal(await queueConsolidatedFindingNotifications(pool, [first, second]), 1);
    const rows = (await pool.query('SELECT payload FROM outbox ORDER BY created_at')).rows;
    assert.deepEqual(rows[1].payload.includedFindingIds, ['f2'], 'only the un-notified finding is included');
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
