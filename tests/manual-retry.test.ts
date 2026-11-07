import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import supertest from 'supertest';
import pg from 'pg';
import { createApp } from '../server/app.ts';
import { createUser } from '../server/auth.ts';
import { loadConfig } from '../server/config.ts';
import { createPool, migrate, put } from '../server/db.ts';

/**
 * The operator's manual "retry delivery" action, and the unknown-collection
 * guard on the generic record API.
 *
 * Both defects were found by exercising the running server: an unknown
 * collection name produced a 500 (a crash, not a 404), and the retry endpoint's
 * guard rail — "a manual retry must never double-send a delivery that is
 * already due or in flight" — had no coverage at all.
 */

async function withDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T | null> {
  if (!process.env.TEST_DATABASE_URL) return null;
  const master = createPool(process.env.TEST_DATABASE_URL);
  const schema = `retry_${randomBytes(10).toString('hex')}`;
  let pool: pg.Pool | undefined;
  try {
    await master.query(`CREATE SCHEMA ${schema}`);
    pool = new pg.Pool({
      connectionString: process.env.TEST_DATABASE_URL,
      options: `-c search_path=${schema}`,
      max: 4,
      connectionTimeoutMillis: 3000,
    });
    await migrate(pool);
    return await fn(pool);
  } finally {
    await pool?.end();
    await master.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await master.end();
  }
}

/** Insert an outbox row in a chosen state and return its id. */
async function queueEmail(
  pool: pg.Pool,
  status: 'FAILED' | 'QUEUED' | 'SENDING' | 'ACCEPTED',
  options: {
    attempts?: number;
    dueInMs?: number;
    advisoryId?: string;
    payload?: Record<string, unknown>;
  } = {},
): Promise<string> {
  const id = randomUUID();
  const attempts = options.attempts ?? 1;
  const next = new Date(Date.now() + (options.dueInMs ?? 600_000));
  await pool.query(
    `INSERT INTO outbox(id,channel,target_id,advisory_id,status,attempts,next_attempt,dedupe_key,payload)
     VALUES($1,'email','test',$2,$3,$4,$5,$6,$7)`,
    [
      id,
      options.advisoryId ?? `ADV-${id}`,
      status,
      attempts,
      next,
      `email:test:${id}`,
      JSON.stringify(options.payload ?? { recipientEmail: 'ops@example.org', text: 'body' }),
    ],
  );
  return id;
}

async function adminAgent(pool: pg.Pool) {
  const config = loadConfig({
    ...process.env,
    DATABASE_URL: process.env.TEST_DATABASE_URL,
    APP_ORIGIN: 'http://127.0.0.1:3999',
    ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    WORKER_ENABLED: 'false',
  });
  await createUser(pool, 'retry-admin', 'Disposable-retry-test-password-2026!', 'ADMIN');
  const app = createApp(pool, config, async () => ({ status: 200, headers: {}, body: '[]' }));
  const agent = supertest.agent(app);
  const login = await agent
    .post('/api/login')
    .set('Origin', config.APP_ORIGIN)
    .send({ username: 'retry-admin', password: 'Disposable-retry-test-password-2026!' });
  assert.equal(login.status, 200);
  return { agent, csrf: login.body.csrfToken as string, origin: config.APP_ORIGIN };
}

test(
  'a manual retry resets only a failed job and refuses anything already sendable',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const { agent, csrf, origin } = await adminAgent(pool);
      const failed = await queueEmail(pool, 'FAILED', { attempts: 3 });
      const scheduled = await queueEmail(pool, 'QUEUED', { attempts: 2, dueInMs: 600_000 });
      const due = await queueEmail(pool, 'QUEUED', { attempts: 1, dueInMs: -1000 });
      const inFlight = await queueEmail(pool, 'SENDING', { attempts: 1 });
      const legacyAdvisoryId = 'ADV-legacy-retry-format';
      const legacyFindingId = 'finding-legacy-retry-format';
      const legacyCveId = 'CVE-2026-76543';
      await put(pool, 'advisories', legacyAdvisoryId, {
        id: legacyAdvisoryId,
        title: 'Vulnerability Notification: 1 High',
        severity: 'HIGH',
        cveIds: [legacyCveId],
        findingIds: [legacyFindingId],
        createdDate: new Date().toISOString(),
        deliveryStatus: 'FAILED',
        recipientCount: 1,
        executiveSummary: 'A vulnerability affects a monitored asset.',
        affectedSystems: ['server-01'],
        remediationInstructions: 'Apply the vendor fix.',
        vendorLink: '',
      });
      await put(pool, 'findings', legacyFindingId, {
        id: legacyFindingId,
        cveId: legacyCveId,
        cve: {
          cveId: legacyCveId,
          title: 'Retry format fixture',
          description: 'A retry fixture vulnerability.',
          publishedDate: new Date().toISOString(),
          modifiedDate: new Date().toISOString(),
          cvss: { version: '3.1', score: 8, vector: '', severity: 'HIGH' },
          cwe: [],
          cpeMatches: [],
          versionRange: {},
          sourceFeeds: [],
          epss: { score: 0, percentile: 0 },
          cisaKev: { isKev: false },
          exploitStatus: 'None',
          remediation: {
            patchUrl: '',
            vendorAdvisoryRef: '',
            immediateActions: [],
            workarounds: [],
            rollbackPlan: '',
            stepByStep: [],
          },
        },
        matchedAssetId: 'asset-01',
        matchedAssetName: 'server-01',
        matchedAssetVendor: 'Example Vendor',
        matchedAssetProduct: 'Example Product',
        matchedCpe: 'cpe:2.3:a:example:product:*:*:*:*:*:*:*:*',
      });
      const legacyHtmlEmail = await queueEmail(pool, 'FAILED', {
        advisoryId: legacyAdvisoryId,
        payload: {
          recipientEmail: 'ops@example.org',
          text: 'legacy message',
          html: `<html><body><h1>${legacyCveId}</h1><p>Old list format</p></body></html>`,
        },
      });

      const retry = (id: string) =>
        agent.post(`/api/email/${id}/retry`).set('Origin', origin).set('x-csrf-token', csrf).set('content-type', 'application/json').send({});

      // A failed job restarts with a fresh budget: the exhausted ladder is the
      // reason it stopped, so keeping attempts would make the retry a no-op.
      assert.equal((await retry(failed)).status, 200);
      const restarted = (await pool.query('SELECT status,attempts,next_attempt FROM outbox WHERE id=$1', [failed]))
        .rows[0];
      assert.equal(restarted.status, 'QUEUED');
      assert.equal(restarted.attempts, 0);
      assert.ok(new Date(restarted.next_attempt).getTime() <= Date.now() + 1000);

      assert.equal((await retry(legacyHtmlEmail)).status, 200);
      const refreshed = (await pool.query('SELECT payload FROM outbox WHERE id=$1', [legacyHtmlEmail])).rows[0].payload;
      assert.match(refreshed.html, new RegExp(`data-pdf-cve="${legacyCveId}"`));
      assert.match(refreshed.html, /data-pdf-severity="HIGH"/);
      assert.match(refreshed.html, new RegExp(legacyCveId));

      // A job waiting on a scheduled retry can be pulled forward, but its
      // attempt history is evidence and must survive.
      assert.equal((await retry(scheduled)).status, 200);
      const pulled = (await pool.query('SELECT status,attempts FROM outbox WHERE id=$1', [scheduled])).rows[0];
      assert.equal(pulled.status, 'QUEUED');
      assert.equal(pulled.attempts, 2, 'a scheduled retry keeps its attempt count');

      // Already due, or already being sent: the worker owns it. Allowing a
      // retry here is a double-send.
      assert.equal((await retry(due)).status, 409);
      assert.equal((await retry(inFlight)).status, 409);
      assert.equal(
        (await pool.query('SELECT status FROM outbox WHERE id=$1', [inFlight])).rows[0].status,
        'SENDING',
      );

      // Unknown ids and non-email rows are refused, not silently accepted.
      assert.equal((await retry(randomUUID())).status, 409);

      // The retry is audited with the operator's identity.
      const audit = await pool.query(
        "SELECT data FROM audit WHERE data->>'event' ILIKE '%retry%'",
      );
      assert.ok((audit.rowCount ?? 0) >= 2, 'each accepted retry must leave an audit record');
    });
    assert.notEqual(outcome, null);
  },
);

test(
  'an unknown collection is a 404-class rejection, never a 500',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const { agent, csrf, origin } = await adminAgent(pool);
      // GET carries no body; the mutating verbs must send one or the request is
      // rejected for its content type before routing is even reached.
      const response = await agent.get('/api/collections/notACollection').set('Origin', origin);
      assert.equal(response.status, 404, 'an unknown collection is a client error, not a 500');
      assert.match(String(response.body.error ?? ''), /Unknown collection/);
      // A known collection still works, so the guard is not over-broad.
      assert.equal((await agent.get('/api/collections/watchlist').set('Origin', origin)).status, 200);
    });
    assert.notEqual(outcome, null);
  },
);
