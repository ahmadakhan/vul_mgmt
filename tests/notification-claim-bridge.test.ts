import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { createPool, migrate, put } from '../server/db.ts';
import { queueConsolidatedFindingNotifications, queueDigestAdvisory, consolidatedFindingsDocument, queueZeroDayDigestNotification, findingHtmlAttachment, type ZeroDayDigestPayload } from '../server/delivery.ts';
import { claimsForJob, claimItems, reconcileDuplicateOutboxClaims } from '../server/deliveryClaims.ts';
import { newsArticleIdentity } from '../server/newsEmail.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { Finding, EmailRecipient } from '../src/types/index.ts';

const database = process.env.TEST_DATABASE_URL;

async function fixture(fn: (pool: pg.Pool) => Promise<void>) {
  const admin = createPool(database!);
  const schema = `notification_claim_${randomBytes(8).toString('hex')}`;
  await admin.query(`CREATE SCHEMA ${schema}`);
  const pool = new pg.Pool({ connectionString: database, options: `-c search_path=${schema}`, max: 4 });
  try {
    await migrate(pool);
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS });
    await put(pool, 'recipients', 'r1', {
      id: 'r1', name: 'SOC', email: 'security@example.invalid', enabled: true,
      deliveryGroup: 'SECURITY_TEAM', subscriptionTier: 'ALL_SEVERITIES', deliverySuccessRate: 1,
    } as EmailRecipient);
    await fn(pool);
  } finally {
    await pool.end();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  }
}

const finding = {
  id: 'f-one', cveId: 'CVE-2026-80001', status: 'MONITORED', notificationStatus: 'REVIEW_REQUIRED',
  matchedAssetId: 'asset-one', matchedAssetName: 'server-1', matchedAssetVendor: 'acme', matchedAssetProduct: 'widget',
  matchedCpe: 'cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*', confidence: 70,
  matchingEvidence: 'Version range is not confirmed by the vendor',
  matchingMethod: 'STRICT_CPE_INTERVAL', exploitRisk: 'NONE',
  advisoryId: null, reviewNotifiedAt: null, autoDispatchedAt: null, timeline: [],
  cve: {
    cveId: 'CVE-2026-80001', title: 'Test issue', description: 'Test issue',
    publishedDate: new Date().toISOString(), modifiedDate: new Date().toISOString(),
    cvss: { severity: 'HIGH', score: 8.1, version: '3.1', vector: '' },
    cwe: [], cpeMatches: ['cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*'],
    remediation: { vendorAdvisoryRef: 'https://vendor.example/issue', immediateActions: [], workarounds: [] },
    epss: { score: 0.02, percentile: 0.1 },
    sourceFeeds: ['NVD'], cisaKev: { isKev: false },
  },
} as unknown as Finding;

test('legacy digest and main consolidated queue share finding claims', { skip: !database }, async () => {
  await fixture(async (pool) => {
    assert.equal(await queueConsolidatedFindingNotifications(pool, [finding]), 1);
    const advisory = consolidatedFindingsDocument([finding], new Date()).advisory;
    const digest = await queueDigestAdvisory(pool, advisory, [finding]);
    assert.equal(digest.jobs, 0);
    const messages = await pool.query("SELECT id FROM outbox WHERE channel='email'");
    assert.equal(messages.rowCount, 1, 'same finding cannot be sent twice through a second queue');
  });
});

test('an accepted outbox job repairs a missing finding claim on dedupe', { skip: !database }, async () => {
  await fixture(async (pool) => {
    const job = await pool.query<{ id: string; dedupe_key: string }>(
      `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,delivery_outcome)
       VALUES(gen_random_uuid(),'old:email:r1','email','r1','FINDINGS:old',
              '{"includedFindingIds":["f-one"]}'::jsonb,'ACCEPTED','ACCEPTED')
       RETURNING id,dedupe_key`,
    );
    const requests = claimsForJob('r1', 'finding', ['f-one']);
    const claimed = await claimItems(pool, requests);
    assert.equal(claimed.granted.length, 1);
    await reconcileDuplicateOutboxClaims(pool, job.rows[0].dedupe_key, claimed.granted);
    const status = await pool.query<{ state: string; job_id: string }>(
      `SELECT state,job_id FROM delivery_claims WHERE recipient_id='r1' AND kind='finding' AND item_id='f-one'`,
    );
    assert.equal(status.rows[0]?.state, 'DELIVERED');
    assert.equal(status.rows[0]?.job_id, job.rows[0].id);
  });
});

test('an accepted news job repairs its article claim; subsequent news is suppressed', { skip: !database }, async () => {
  await fixture(async (pool) => {
    const article = { id: 'feed-1', url: 'https://example.com/story?id=123&utm_source=feed' };
    const articleIdentity = newsArticleIdentity(article);
    const job = await pool.query<{ id: string; dedupe_key: string }>(
      `INSERT INTO outbox(id,dedupe_key,channel,target_id,advisory_id,payload,status,delivery_outcome)
       VALUES(gen_random_uuid(),'news-old:email:r1','email','r1','NEWS:feed-1',
              $1::jsonb,'ACCEPTED','ACCEPTED')
       RETURNING id,dedupe_key`,
      [JSON.stringify({ newsEvidence: { articles: [article] } })],
    );
    const requests = claimsForJob('r1', 'article', [articleIdentity]);
    assert.equal((await claimItems(pool, requests)).granted.length, 1);
    await reconcileDuplicateOutboxClaims(pool, job.rows[0].dedupe_key, requests);
    const claim = await pool.query<{ state: string }>(
      `SELECT state FROM delivery_claims WHERE recipient_id='r1' AND kind='article' AND item_id=$1`,
      [articleIdentity],
    );
    assert.equal(claim.rows[0]?.state, 'DELIVERED');
    assert.equal((await claimItems(pool, requests)).granted.length, 0);
  });
});


test('Security-first defers only findings Security is subscribed to', { skip: !database }, async () => {
  await fixture(async (pool) => {
    await put(pool, 'settings', 'main', {
      ...DEFAULT_SETTINGS, deferEveryoneUntilSecurityDelivered: true,
    });
    await put(pool, 'recipients', 'r1', {
      id: 'r1', name: 'Security', email: 'security@example.invalid', enabled: true,
      deliveryGroup: 'SECURITY_TEAM', subscriptionTier: 'CRITICAL_HIGH_ONLY', deliverySuccessRate: 1,
    } as EmailRecipient);
    await put(pool, 'recipients', 'r2', {
      id: 'r2', name: 'Everyone', email: 'everyone@example.invalid', enabled: true,
      deliveryGroup: 'EVERYONE', subscriptionTier: 'ALL_SEVERITIES', deliverySuccessRate: 1,
    } as EmailRecipient);
    const low = {
      ...finding, id: 'f-low', cveId: 'CVE-2026-80002',
      cve: { ...finding.cve, cveId: 'CVE-2026-80002', cvss: { ...finding.cve.cvss, severity: 'LOW', score: 3.0 } },
    } as Finding;
    assert.equal(await queueConsolidatedFindingNotifications(pool, [finding, low]), 2);
    const rows = await pool.query<{ target_id: string; payload: { includedFindingIds: string[] } }>(
      "SELECT target_id,payload FROM outbox WHERE channel='email' AND status='QUEUED' ORDER BY target_id",
    );
    assert.deepEqual(rows.rows.map((r) => [r.target_id, r.payload.includedFindingIds]), [
      ['r1', ['f-one']], ['r2', ['f-low']],
    ]);
  });
});


test('an oversized findings HTML attachment fails before any provider send', () => {
  assert.throws(() => findingHtmlAttachment({
    advisory_id: 'FINDINGS:too-large',
    payload: { html: '<html>' + 'x'.repeat(4_000_001) + '</html>' },
  } as unknown as import('../server/delivery.ts').Job), /exceeds the attachment limit/);
});
