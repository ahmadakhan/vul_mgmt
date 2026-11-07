import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID, createHmac } from 'node:crypto';
import supertest from 'supertest';
import { createPool, migrate, transaction, get, list, put, remove } from '../server/db.ts';
import { createApp } from '../server/app';
import { createDatabaseRateLimiter } from '../server/rateLimit';
import { createUser } from '../server/auth';
import { loadConfig } from '../server/config.ts';
import { decrypt, encrypt, passwordHash, checkPassword } from '../server/secrets.ts';
import { publicAddress, resolvePublic, type Requester } from '../server/network';
import { normalizeNvd } from '../server/ingestion';
import { ingestFeed } from '../server/ingestion';
import { processPipeline, queueRun } from '../server/pipeline';
import { deliverNext } from '../server/delivery';
import { verifyAuditChain } from '../src/utils/cryptoChain';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { NormalizedCVE, Finding, Advisory, WebhookEndpoint } from '../src/types/index.ts';
const database = process.env.TEST_DATABASE_URL;
const key = randomBytes(32).toString('base64');
const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: database || 'postgres://unused',
  APP_ORIGIN: 'http://localhost',
  ENCRYPTION_KEY: key,
  EGRESS_ALLOWED_HOSTS: '8.8.8.8,filestore.fortinet.com',
  WORKER_ENABLED: 'false',
});
const password = 'Integration-test-password-2026!';
const cpe = (version: string) => `cpe:2.3:a:example:widget:${version}:*:*:*:*:*:*:*`;
function fixture(): NormalizedCVE {
  return {
    cveId: 'CVE-2026-12345',
    title: 'Widget test vulnerability',
    description: 'Test fixture',
    publishedDate: new Date().toISOString(),
    modifiedDate: new Date().toISOString(),
    cvss: { version: '3.1', score: 9.8, vector: '', severity: 'CRITICAL' },
    cwe: [],
    cpeMatches: [cpe('*')],
    versionRange: { versionEndExcluding: '2.0' },
    sourceFeeds: ['operator-import'],
    epss: { score: 0.5, percentile: 0.9 },
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
  };
}
test('configuration rejects absent secrets and insecure production origin', () => {
  assert.throws(() => loadConfig({}), /./);
  assert.throws(
    () =>
      loadConfig({
        ...Object.fromEntries(Object.entries(config).map(([k, v]) => [k, String(v)])),
        NODE_ENV: 'production',
      }),
    /HTTPS/,
  );
});
test('encryption authenticates ciphertext and its record context', () => {
  const secret = encrypt('private-value', [key], 'record:1');
      assert.equal(decrypt(secret, [key], 'record:1'), 'private-value');
      assert.throws(() => decrypt(secret, [key], 'record:2'));
      assert.throws(() => decrypt(secret.replace(/.$/, 'x'), [key], 'record:1'));
});
test('password hashes are salted and verify only the correct password', async () => {
  const hash = await passwordHash(password);
  assert.equal(await checkPassword(password, hash), true);
  assert.equal(await checkPassword('wrong', hash), false);
  assert.notEqual(hash, await passwordHash(password));
});
test('outbound DNS screening rejects private, mapped and mixed resolutions', async () => {
  for (const ip of [
    '127.0.0.1',
    '::1',
    '::ffff:127.0.0.1',
    '10.1.2.3',
    '169.254.169.254',
    '100.64.1.2',
    'fc00::1',
    '192.0.2.1',
  ])
    assert.equal(publicAddress(ip), false, ip);
  assert.equal(publicAddress('8.8.8.8'), true);
  await assert.rejects(
    resolvePublic(new URL('https://example.com'), ['example.com'], (async () => [
      { address: '8.8.8.8', family: 4 },
      { address: '10.0.0.1', family: 4 },
    ]) as any),
    /non-public/,
  );
  await assert.rejects(resolvePublic(new URL('https://8.8.8.8'), []), /allow|EGRESS/);
  await assert.rejects(resolvePublic(new URL('http://8.8.8.8'), ['8.8.8.8']), /HTTPS/);
});
test('NVD normalization preserves per-CPE ranges and does not flatten AND conditions', () => {
  const input = {
    cve: {
      id: 'CVE-2026-12345',
      vulnStatus: 'Analyzed',
      published: '2026-10-20T01:00:00',
      lastModified: '2026-10-20T01:00:00',
      descriptions: [{ lang: 'en', value: 'Test' }],
      metrics: { cvssMetricV31: [{ cvssData: { version: '3.1', baseScore: 9.8, vectorString: '' } }] },
      configurations: [
        {
          nodes: [
            {
              operator: 'OR',
              cpeMatch: [{ vulnerable: true, criteria: cpe('*'), versionEndExcluding: '2.0' }],
            },
          ],
        },
      ],
    },
  };
  assert.equal(normalizeNvd(input, 'source')?.cpeMatchDetails?.[0].range?.versionEndExcluding, '2.0');
  input.cve.configurations[0].nodes[0].operator = 'AND';
  assert.equal(normalizeNvd(input, 'source')?.applicabilityRequiresReview, true);
  assert.equal(normalizeNvd(input, 'source')?.cpeMatches.length, 1);
});
test('unscored NVD vulnerabilities remain matchable without inventing a severity', () => {
  const input = {
    cve: {
      id: 'CVE-2026-12345',
      vulnStatus: 'Analyzed',
      published: '2026-10-20T01:00:00Z',
      lastModified: '2026-10-20T01:00:00Z',
      descriptions: [{ lang: 'en', value: 'Unscored vulnerability' }],
      metrics: {},
      configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [{ vulnerable: true, criteria: cpe('*') }] }] }],
    },
  };
  const normalized = normalizeNvd(input, 'nvd');
  assert.equal(normalized?.cvss.version, 'UNKNOWN');
  assert.equal(normalized?.cvss.severity, 'UNKNOWN');
  assert.equal(normalized?.cvss.score, 0);
  assert.equal(normalized?.cpeMatches.length, 1);
});
test('NVD uses bounded large-page requests and honors rate-limit retries', async () => {
  const headers: Record<string, string>[] = [];
  const requestLimits: { timeoutMs?: number; socketTimeoutMs?: number; maxResponseBytes?: number }[] = [];
  const feed = {
    id: 'nvd',
    name: 'NVD',
    type: 'NVD_API' as const,
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    authType: 'NONE' as const,
    authSecretKey: '',
    rateLimitPerMin: 10,
    enabled: true,
    healthStatus: 'UNTESTED' as const,
    lastSync: null,
    latencyMs: 0,
    vendorSeed: true,
    itemCountLastRun: 0,
    ssrfValidated: false,
    etag: 'stale-page-etag',
  };
  await ingestFeed(
    feed,
    24,
    async (rawUrl, options) => {
      assert.equal(new URL(rawUrl).searchParams.get('resultsPerPage'), '2000');
      headers.push(options?.headers || {});
      requestLimits.push({
        timeoutMs: options?.timeoutMs,
        socketTimeoutMs: options?.socketTimeoutMs,
        maxResponseBytes: options?.maxResponseBytes,
      });
      return {
        status: 200,
        body: JSON.stringify({ vulnerabilities: [], totalResults: 0, startIndex: 0 }),
        headers: {},
      };
    },
    config,
  );
  assert.equal(headers.length, 1);
  assert.equal(headers[0]['If-None-Match'], undefined);
  assert.deepEqual(requestLimits, [
    { timeoutMs: 120000, socketTimeoutMs: 60000, maxResponseBytes: 32 * 1024 * 1024 },
  ]);

  const retryDelays: number[] = [];
  let retryCalls = 0;
  await ingestFeed(
    feed,
    24,
    async () => {
      retryCalls++;
      return retryCalls === 1
        ? { status: 429, body: '', headers: { 'retry-after': '2' } }
        : {
            status: 200,
            body: JSON.stringify({ vulnerabilities: [], totalResults: 0, startIndex: 0 }),
            headers: {},
          };
    },
    config,
    async <T = void>(ms = 0, value?: T): Promise<T> => {
      retryDelays.push(ms);
      return value as T;
    },
  );
  assert.equal(retryCalls, 2);
  assert.deepEqual(retryDelays, [6100]);

  const timeoutDelays: number[] = [];
  let timeoutCalls = 0;
  await ingestFeed(
    feed,
    24,
    async () => {
      timeoutCalls++;
      if (timeoutCalls === 1) throw new Error('Outbound request timed out');
      return {
        status: 200,
        body: JSON.stringify({ vulnerabilities: [], totalResults: 0, startIndex: 0 }),
        headers: {},
      };
    },
    config,
    async <T = void>(ms = 0, value?: T): Promise<T> => {
      timeoutDelays.push(ms);
      return value as T;
    },
  );
  assert.equal(timeoutCalls, 2);
  assert.deepEqual(timeoutDelays, [6100]);
});

test('PostgreSQL API, auth, pipeline, durable delivery and recovery', { skip: !database }, async (t) => {
  const base = createPool(database!);
  const schema = 'test_' + randomUUID().replaceAll('-', '');
  await base.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href);
  let capturedUrl = '',
    capturedUrls: string[] = [],
    capturedBody = '',
    capturedMethod = '',
    capturedHeaders: Record<string, string> = {},
    responseStatus = 200,
    responseBody = '[]';
  const requester: Requester = async (_url, options) => {
    capturedUrl = _url;
    capturedUrls.push(_url);
    capturedBody = options?.body || '';
    capturedMethod = options?.method || 'GET';
    capturedHeaders = options?.headers || {};
    return { status: responseStatus, body: responseBody, headers: {} };
  };
  try {
    await migrate(pool);
    await migrate(pool);
    await createUser(pool, 'admin', password, 'ADMIN');
    await createUser(pool, 'operator', password, 'OPERATOR');
    await createUser(pool, 'viewer', password, 'VIEWER');
    const app = createApp(pool, config, requester),
      admin = supertest.agent(app),
      viewer = supertest.agent(app),
      operator = supertest.agent(app);
    const login = async (agent: ReturnType<typeof supertest.agent>, username: string) => {
      const r = await agent.post('/api/login').set('Origin', config.APP_ORIGIN).send({ username, password });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      return r.body.csrfToken as string;
    };
    const csrf = await login(admin, 'admin'),
      viewCsrf = await login(viewer, 'viewer'),
      opCsrf = await login(operator, 'operator');
    const post = (route: string, data: any = {}) =>
      admin.post(route).set('Origin', config.APP_ORIGIN).set('x-csrf-token', csrf).send(data);
    const command = (action: string, data?: any, id?: string) => post('/api/commands', { action, data, id });
    await t.test('ML status and analyst feedback enforce authentication, roles and validation', async () => {
      assert.equal((await supertest(app).get('/api/ml/status')).status, 401);
      const status = await viewer.get('/api/ml/status');
      assert.equal(status.status, 200);
      assert.equal(status.body.totalModels, 18);
      assert.equal(status.body.models.length, 18);
      const feedback = { source: 'calibrationPairs', sample: { credibilityScore: 75, isActionable: true } };
      assert.equal((await viewer.post('/api/ml/feedback').set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', viewCsrf).send(feedback)).status, 403);
      assert.equal((await admin.post('/api/ml/feedback').set('Origin', config.APP_ORIGIN).send(feedback)).status, 403);
      assert.equal((await post('/api/ml/feedback', { ...feedback, sample: { credibilityScore: 101, isActionable: true } })).status, 400);
      const feedbackResponse = await post('/api/ml/feedback', feedback);
      assert.equal(feedbackResponse.status, 201);
      assert.deepEqual(feedbackResponse.body, {
        recorded: true,
        source: feedback.source,
        effect: 'next_training_run',
      });
      const saved = await pool.query("SELECT id,context FROM operational_events WHERE code='ml.training.feedback' ORDER BY id DESC LIMIT 1");
      assert.deepEqual(saved.rows[0].context, feedback);
      await pool.query('DELETE FROM operational_events WHERE id=$1', [saved.rows[0].id]);
    });
    await t.test('unauthenticated reads, CSRF and foreign origins are rejected', async () => {
      assert.equal((await supertest(app).get('/api/state')).status, 401);
      assert.equal((await supertest(app).get('/api/events')).status, 401);
      assert.equal((await viewer.get('/api/events')).status, 200);
      assert.equal((await viewer.get('/api/events?before=9999999999999999999')).status, 400);
      assert.equal((await viewer.get('/api/events?category=INVALID')).status, 400);
      assert.equal((await viewer.get('/api/collections/notACollection')).status, 404);
      assert.equal((await viewer.get('/api/collections/cveData?limit=1')).status, 200);
      assert.equal(
        (
          await admin
            .post('/api/commands')
            .set('Origin', config.APP_ORIGIN)
            .send({ action: 'asset.delete', id: 'x' })
        ).status,
        403,
      );
      assert.equal(
        (
          await admin
            .post('/api/commands')
            .set('Origin', 'https://evil.test')
            .set('x-csrf-token', csrf)
            .send({})
        ).status,
        403,
      );
      const response = await admin.get('/api/state');
      assert.equal(response.status, 200);
      assert.match(response.headers['content-security-policy'], /script-src 'self'/);
      assert.equal(response.headers['cache-control'], 'no-store');
      assert.equal(response.body.watchlist.length, 0);
      const compressed = await admin.get('/api/state').set('Accept-Encoding', 'gzip');
      assert.equal(
        compressed.headers['content-encoding'],
        'gzip',
        'the large state snapshot must be gzip-compressed in transit',
      );
    });
    await t.test('pipeline stop enforces authentication, CSRF and operator roles', async () => {
      const path = '/api/pipeline/missing/stop';
      assert.equal((await supertest(app).post(path).set('Origin', config.APP_ORIGIN).send({})).status, 401);
      assert.equal((await admin.post(path).set('Origin', config.APP_ORIGIN).send({})).status, 403);
      assert.equal(
        (await viewer.post(path).set('Origin', config.APP_ORIGIN).set('x-csrf-token', viewCsrf).send({}))
          .status,
        403,
      );
      assert.equal(
        (await operator.post(path).set('Origin', config.APP_ORIGIN).set('x-csrf-token', opCsrf).send({}))
          .status,
        404,
      );
    });
    await t.test('roles enforce write and administration boundaries', async () => {
      assert.equal(
        (
          await viewer
            .post('/api/pipeline')
            .set('Origin', config.APP_ORIGIN)
            .set('x-csrf-token', viewCsrf)
            .send({})
        ).status,
        403,
      );
      assert.equal(
        (
          await operator
            .post('/api/commands')
            .set('Origin', config.APP_ORIGIN)
            .set('x-csrf-token', opCsrf)
            .send({ action: 'settings.save', data: { schedulerEnabled: true } })
        ).status,
        403,
      );
      // Fail closed at the HTTP boundary: an action that is not in either
      // classification set is rejected with 400 before the dispatcher sees it,
      // so a typo or a future unclassified action cannot inherit implicit
      // OPERATOR authorization (mirrors assertCommandRole unit coverage).
      const unknown = await operator
        .post('/api/commands')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', opCsrf)
        .send({ action: 'feed.nuke', data: {} });
      assert.equal(unknown.status, 400, 'unknown actions must fail closed with 400');
      assert.match(unknown.body.error, /Unknown command/i);
      assert.equal((await operator.get('/api/users')).status, 403);
      // VIEWER is read-only, not blind: read endpoints and read-only
      // simulations stay available while every mutation is role-gated.
      assert.equal((await viewer.get('/api/audit/verify')).status, 200);
      assert.equal((await viewer.get('/api/email-queue')).status, 200);
      const viewerPage = await viewer.get('/api/collections/auditLogs?limit=2&offset=2');
      assert.equal(viewerPage.status, 200);
      assert.equal(
        viewerPage.body.offset,
        2,
        'VIEWER pagination must not be silently reset to the first page',
      );
      const viewerSearch = await viewer.get('/api/collections/auditLogs?search=no-such-audit-entry-zz');
      assert.equal(viewerSearch.status, 200);
      assert.equal(viewerSearch.body.total, 0, 'VIEWER collection search must be applied');
      const simulated = await viewer
        .post('/api/correlation/simulate')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', viewCsrf)
        .send({ vendor: 'acme', product: 'widget' });
      assert.equal(simulated.status, 200, JSON.stringify(simulated.body));
      // An operator-level action executes under a non-admin role end to end,
      // proving the fail-closed gate only blocks what it should.
      const opWrite = await operator
        .post('/api/commands')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', opCsrf)
        .send({
          action: 'cve.save',
          data: { cveId: 'CVE-2026-90001', title: 'Operator-imported CVE', description: 'Role check', publishedDate: '2026-01-01T00:00:00Z', modifiedDate: '2026-01-01T00:00:00Z', cvss: { version: '3.1', score: 5, vector: '', severity: 'MEDIUM' }, cwe: [], cpeMatches: [], sourceFeeds: [], epss: { score: 0, percentile: 0 }, cisaKev: { isKev: false }, exploitStatus: 'None', remediation: { patchUrl: '', vendorAdvisoryRef: '', immediateActions: [], workarounds: [], rollbackPlan: '', stepByStep: [] } },
        });
      assert.equal(opWrite.status, 200, JSON.stringify(opWrite.body));
      // Remove the record so later subtests (retention scan counts, collection
      // totals) observe the same baseline they did before this check ran.
      await remove(pool, 'cveData', 'CVE-2026-90001');
    });
    await t.test('mutation quota is shared across application replicas', async () => {
      const username = 'rate-operator';
      // The subject of this test is quota propagation, not authorization, so it
      // needs a role that can actually mutate. A VIEWER has no write endpoint at
      // all (verified by the role-boundary test above), so using one here only
      // tested the 403 path.
      await createUser(pool, username, password, 'OPERATOR');
      const replicaA = createApp(pool, config, requester, {
        mutationLimiter: createDatabaseRateLimiter(pool, 2, 0.000001),
      });
      const replicaB = createApp(pool, config, requester, {
        mutationLimiter: createDatabaseRateLimiter(pool, 2, 0.000001),
      });
      const agentA = supertest.agent(replicaA),
        agentB = supertest.agent(replicaB);
      const loginReplica = async (agent: typeof agentA) => {
        const response = await agent
          .post('/api/login')
          .set('Origin', config.APP_ORIGIN)
          .send({ username, password });
        assert.equal(response.status, 200, JSON.stringify(response.body));
        return response.body.csrfToken as string;
      };
      const csrfA = await loginReplica(agentA),
        csrfB = await loginReplica(agentB);
      // Buckets are keyed per operator id and persist across runs and replicas.
      // Login itself is a POST that charges the bucket, and earlier tests in
      // this suite consume quota for other users, so the limit must be measured
      // from a known-zero baseline run under this operator's identity.
      //
      // The bucket write happens in each replica's own pool, which uses the
      // suite's isolated schema; this pool is created with the same search_path.
      const operatorId = (
        await pool.query<{ id: string }>('SELECT id FROM users WHERE username=$1', [username])
      ).rows[0]?.id;
      assert.ok(operatorId, 'operator row must exist for quota isolation');
      await pool.query('DELETE FROM rate_limit_buckets WHERE bucket_key=$1', [`rl:${operatorId}`]);
      // The quota is charged by genuine asset.save mutations. Every mutation in
      // this one suite shares an isolated schema, and earlier tests already
      // register `quota/probe`; a pre-existing identical row made this test's
      // first mutation a 409 that consumed no quota, so the third call was
      // admitted instead of throttled. Removing any row with this identity
      // (whatever its tag) keeps the probe a genuine first write.
      const removed = await pool.query(
        "DELETE FROM records WHERE kind='watchlist' AND (lower(data->>'vendor')='quota' OR data->>'assetTag' LIKE 'QUOTA-PROBE%')",
      );
      const leftovers = await pool.query(
        "SELECT count(*)::int AS n FROM records WHERE kind='watchlist' AND lower(data->>'vendor')='quota'",
      );
      assert.equal(leftovers.rows[0].n, 0, `probe rows must be removed first (removed=${removed.rowCount})`);
      // Charge the shared quota with genuine mutations. It previously used
      // /api/correlation/simulate, which performs no writes and is therefore
      // exempt from the mutation quota — the exemption is asserted separately
      // below so both behaviours stay pinned.
      const mutate = (agent: typeof agentA, csrf: string, product = 'probe') =>
        agent
          .post('/api/commands')
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', csrf)
          // asset.save is the lowest-privilege genuine mutation: OPERATOR may
          // run it and it writes a watchlist row, so it charges the shared
          // bucket. settings.save is ADMIN-only, which made this test assert
          // 403 instead of quota propagation.
          .send({
            action: 'asset.save',
            data: {
              vendor: 'quota',
              product,
              cpes: ['cpe:2.3:a:quota:probe:1.0:*:*:*:*:*:*:*'],
              active: true,
              assetTag: `QUOTA-PROBE-${product}`,
              ownerGroup: 'Platform',
            },
          });
      const first = await mutate(agentA, csrfA);
      assert.equal(first.status, 200, JSON.stringify(first.body));
      // Prove the write really happened before asserting anything about quota.
      const written = await pool.query(
        "SELECT count(*)::int AS n FROM records WHERE kind='watchlist' AND data->>'assetTag'='QUOTA-PROBE-probe'",
      );
      assert.equal(written.rows[0].n, 1, 'the first mutation must persist the probe row');
      // Replica B must observe what replica A committed before its own save is
      // judged; otherwise the identical write is a fresh insert rather than a
      // distinct mutation, and the throttling assertion below would prove
      // nothing. A replica that polls (as production replicas do) picks the row
      // up; this waits for that, and then saves a *different* product so the
      // test cannot pass merely because B's stale view rejected the duplicate.
      const observedByB = async () => {
        const replicaView = await agentB.get('/api/state');
        return (
          replicaView.status === 200 &&
          JSON.stringify(replicaView.body.watchlist ?? []).includes('QUOTA-PROBE')
        );
      };
      for (let attempt = 0; attempt < 20 && !(await observedByB()); attempt++)
        await new Promise((resolve) => setTimeout(resolve, 100));
      assert.ok(await observedByB(), 'replica B must observe the row replica A committed');
      const second = await mutate(agentB, csrfB, 'probe-b');
      assert.equal(second.status, 200, JSON.stringify(second.body));
      const denied = await mutate(agentA, csrfA);
      assert.equal(denied.status, 429, "the second replica must observe the first replica's consumption");
      assert.ok(Number(denied.headers['retry-after']) >= 1);
      // A read-only simulation is not a mutation: it must still work after the
      // write quota is exhausted, otherwise exploring the matcher burns the
      // operator's ability to change anything.
      const simulatedAfterQuota = await agentA
        .post('/api/correlation/simulate')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', csrfA)
        .send({ vendor: 'acme', product: 'widget' });
      assert.equal(simulatedAfterQuota.status, 200, JSON.stringify(simulatedAfterQuota.body));
      // Reads stay available after the mutation quota is exhausted.
      assert.equal((await agentB.get('/api/state')).status, 200);
    });

    await t.test('validation rejects malformed data and unsupported feed adapters', async () => {
      assert.equal((await command('asset.import', [null])).status, 400);
      assert.equal((await command('feed.save', { url: 'http://127.0.0.1' })).status, 400);
      const bad = await command('settings.save', {
        ssrfProtection: { blockPrivateIps: false, blockLoopback: true, allowRedirects: false },
      });
      assert.equal(bad.status, 400);
      const feed = await command('feed.save', {
        name: 'unsupported',
        type: 'STIX',
        url: 'https://8.8.8.8',
        authType: 'NONE',
        rateLimitPerMin: 1,
        enabled: false,
      });
      assert.equal(feed.status, 400);
      const autoAllowedFeed = await command('feed.save', {
        name: 'Auto-allowed public RSS host',
        type: 'RSS_ATOM',
        url: 'https://1.1.1.1/security.rss',
        authType: 'NONE',
        rateLimitPerMin: 5,
        enabled: false,
      });
      assert.equal(autoAllowedFeed.status, 200, JSON.stringify(autoAllowedFeed.body));
      const unlistedWebhook = await command('webhook.save', {
        name: 'Unlisted destination',
        url: 'https://1.1.1.1/hook',
        provider: 'SLACK',
        secretToken: '',
        enabled: true,
        events: ['ALL'],
      });
      assert.equal(unlistedWebhook.status, 400, 'feed host allowance must not expand webhook egress');
    });
    await t.test('vendor-seeded feeds cannot be deleted but can be toggled', async () => {
      const seeded = await command('feed.save', {
        name: 'Seeded NVD',
        type: 'NVD_API',
        url: 'https://8.8.8.8/nvd',
        authType: 'NONE',
        rateLimitPerMin: 10,
        enabled: true,
        vendorSeed: true,
      });
      assert.equal(seeded.status, 200);
      const seededFeed = (await list<any>(pool, 'feeds')).find((f) => f.name === 'Seeded NVD');
      assert.ok(seededFeed, 'Seeded NVD feed should exist in database');
      assert.equal(
        (await command('feed.save', {
          name: 'Duplicate Seeded NVD',
          type: 'NVD_API',
          url: 'https://8.8.8.8/nvd#duplicate',
          authType: 'NONE',
          rateLimitPerMin: 10,
          enabled: true,
        })).status,
        409,
        'a second feed must not be added for an existing endpoint',
      );
      assert.equal(
        (await command('feed.import', [{
          id: 'duplicate-seeded-nvd',
          name: 'Imported Duplicate NVD',
          type: 'NVD_API',
          url: 'https://8.8.8.8/nvd',
          authType: 'NONE',
          rateLimitPerMin: 10,
          enabled: true,
        }])).status,
        409,
        'bulk import must reject endpoint duplicates too',
      );
      assert.equal(
        (await command('feed.delete', undefined, seededFeed.id)).status,
        403,
        'vendor-seeded feed should be rejected',
      );
      assert.equal(
        (await command('feed.toggle', undefined, seededFeed.id)).status,
        200,
        'vendor-seeded feed should be toggleable',
      );
      const custom = await command('feed.save', {
        name: 'Custom Feed',
        type: 'RSS_ATOM',
        url: 'https://8.8.8.8/feed',
        authType: 'NONE',
        rateLimitPerMin: 5,
        enabled: false,
      });
      assert.equal(custom.status, 200);
      const customFeed = (await list<any>(pool, 'feeds')).find((f) => f.name === 'Custom Feed');
      assert.ok(customFeed, 'Custom Feed should exist in database');
      const customResult = await command('feed.delete', undefined, customFeed.id);
      assert.equal(customResult.status, 200);
    });
    await t.test('non-vendor-seeded NVD feeds cannot be deleted but can be toggled', async () => {
      const nvd = await command('feed.save', {
        name: 'Custom NVD',
        type: 'NVD_API',
        url: 'https://8.8.8.8/custom-nvd',
        authType: 'NONE',
        rateLimitPerMin: 10,
        enabled: true,
        vendorSeed: false,
      });
      assert.equal(nvd.status, 200);
      const nvdFeed = (await list<any>(pool, 'feeds')).find((f) => f.name === 'Custom NVD');
      assert.ok(nvdFeed, 'Custom NVD feed should exist in database');
      assert.equal(
        (await command('feed.delete', undefined, nvdFeed.id)).status,
        403,
        'non-vendor-seeded NVD feed should be rejected',
      );
      assert.equal(
        (await command('feed.toggle', undefined, nvdFeed.id)).status,
        200,
        'non-vendor-seeded NVD feed should be toggleable',
      );
    });
    await t.test('retention policy persists through settings.save', async () => {
      const retentionConfig = {
        enabled: true,
        retentionHours: 336,
        cleanupIntervalMinutes: 30,
        maxArchivedRecords: 250000,
        autoCleanup: true,
        retentionMode: 'strict',
      };
      assert.equal((await command('settings.save', { retentionConfig })).status, 200);
      const state = await admin.get('/api/state');
      assert.equal(state.status, 200);
      assert.deepEqual(state.body.settings.retentionConfig, retentionConfig);
      assert.equal(
        (await command('settings.save', { retentionConfig: { ...retentionConfig, retentionHours: 0 } }))
          .status,
        400,
      );
    });
    await t.test('manual retention run deletes only expired removable records', async () => {
      const retentionConfig = {
        enabled: true,
        retentionHours: 24,
        cleanupIntervalMinutes: 30,
        maxArchivedRecords: 250000,
        autoCleanup: true,
        retentionMode: 'strict' as const,
      };
      assert.equal((await command('settings.save', { retentionConfig })).status, 200);
      const old = new Date(Date.now() - 48 * 3_600_000).toISOString();
      const recent = new Date(Date.now() - 3_600_000).toISOString();
      await put(pool, 'cveData', 'retention-old-cve', { cveId: 'CVE-2026-0001', publishedDate: old });
      await put(pool, 'cveData', 'retention-recent-cve', { cveId: 'CVE-2026-0002', publishedDate: recent });
      await put(pool, 'emailLogs', 'retention-old-email', { id: 'retention-old-email', sentAt: old });
      await put(pool, 'findings', 'retention-protected-finding', {
        id: 'retention-protected-finding',
        timeline: [{ timestamp: old }],
      });

      assert.equal(
        (
          await operator
            .post('/api/retention/run')
            .set('Origin', config.APP_ORIGIN)
            .set('x-csrf-token', opCsrf)
            .send({})
        ).status,
        403,
      );
      const run = await post('/api/retention/run');
      assert.equal(run.status, 200, JSON.stringify(run.body));
      assert.equal(run.body.mode, 'strict');
      assert.equal(run.body.scanned, 3);
      assert.equal(run.body.deleted, 2);
      assert.equal(run.body.byKind.cveData, 1);
      assert.equal(run.body.byKind.emailLogs, 1);

      const remaining = (
        await pool.query('SELECT id FROM records WHERE id = ANY($1::text[]) ORDER BY id', [
          ['retention-old-cve', 'retention-recent-cve', 'retention-old-email', 'retention-protected-finding'],
        ])
      ).rows.map((row) => row.id);
      assert.deepEqual(remaining, ['retention-protected-finding', 'retention-recent-cve']);
      const audit = (await pool.query("SELECT data FROM audit WHERE data->>'event'='Retention cleanup'"))
        .rows[0]?.data;
      assert.ok(audit, 'retention cleanup must be audited');
      assert.match(audit.details, /2 record\(s\) removed/);

      assert.equal(
        (await command('settings.save', { retentionConfig: { ...retentionConfig, enabled: false } })).status,
        200,
      );
      assert.equal((await post('/api/retention/run')).status, 400);
      // Later pipeline tests consume every cveData record, so never leave fixtures behind.
      await pool.query("DELETE FROM records WHERE id LIKE 'retention-%'");
    });
    await t.test('monitored product search requests NVD CPE API 2.0 with header authentication', async () => {
      const feedId = 'cpe-search-test-key';
      const cpeName = 'cpe:2.3:o:microsoft:windows_10:22h2:*:*:*:*:*:*:*';
      await put(pool, 'feeds', feedId, {
        id: feedId, type: 'NVD_API', authType: 'API_KEY', enabled: true,
        authSecretKey: encrypt('cpe-test-api-key', [key], `feed:${feedId}`),
      });
      try {
        responseBody = JSON.stringify({ totalResults: 1, products: [{ cpe: { cpeName, cpeNameId: 'test-cpe-id' } }] });
        const result = await operator.get('/api/cpes/search').query({ vendor: 'Microsoft', product: 'windows_10', limit: 50 });
        assert.equal(result.status, 200, JSON.stringify(result.body));
        assert.equal(result.body.results[0].cpeName, cpeName);
        assert.equal(capturedUrls.length, 2, 'keyword search followed by wildcard-vendor search');
        const keywordUrl = new URL(capturedUrls[0]);
        assert.equal(keywordUrl.origin + keywordUrl.pathname, 'https://services.nvd.nist.gov/rest/json/cpes/2.0');
        assert.equal(keywordUrl.searchParams.get('keywordSearch'), 'Microsoft windows 10');
        assert.equal(keywordUrl.searchParams.has('apiKey'), false);
        assert.equal(capturedHeaders.apiKey, 'cpe-test-api-key');
        const wildcardUrl = new URL(capturedUrls[1]);
        assert.equal(wildcardUrl.searchParams.get('cpeMatchString'), 'cpe:2.3:*:*:windows_10:*:*:*:*:*:*:*:*');
        assert.equal(wildcardUrl.searchParams.has('keywordSearch'), false);
        responseStatus = 404;
        responseBody = '';
        const failed = await operator.get('/api/cpes/search').query({ vendor: 'Microsoft', product: 'Windows' });
        assert.equal(failed.status, 502, 'upstream failures must not look like empty CPE searches');
      } finally {
        responseStatus = 200;
        responseBody = '[]';
        capturedUrl = '';
        capturedUrls = [];
        await pool.query("DELETE FROM records WHERE kind='feeds' AND id=$1", [feedId]);
      }
    });
    await t.test('RSS connectivity tests use the reader identity and validate the feed response', async () => {
      const feedId = 'rss-reader-test';
      await put(pool, 'feeds', feedId, {
        id: feedId, name: 'BleepingComputer Security News', type: 'RSS_ATOM',
        url: 'https://www.bleepingcomputer.com/feed/', authType: 'NONE',
        enabled: false, rateLimitPerMin: 1, healthStatus: 'UNTESTED',
      });
      try {
        responseBody = '<rss version="2.0"><channel><title>BleepingComputer</title></channel></rss>';
        const tested = await post(`/api/feeds/${feedId}/test`);
        assert.equal(tested.status, 200);
        assert.equal(tested.body.success, true);
        assert.equal(capturedUrl, 'https://www.bleepingcomputer.com/feed/');
        assert.equal(capturedHeaders['user-agent'], 'VulnStream/1.0 RSS reader');
        assert.match(capturedHeaders.accept, /application\/rss\+xml/);
        assert.equal((await get<any>(pool, 'feeds', feedId)).healthStatus, 'HEALTHY');

        responseStatus = 403;
        responseBody = '<html>Forbidden</html>';
        const denied = await post(`/api/feeds/${feedId}/test`);
        assert.equal(denied.body.success, false);
        assert.match(denied.body.error, /HTTP 403/);
        assert.equal((await get<any>(pool, 'feeds', feedId)).healthStatus, 'DOWN');

        responseStatus = 200;
        responseBody = '<html>Challenge</html>';
        assert.equal((await post(`/api/feeds/${feedId}/test`)).body.success, false);
      } finally {
        responseStatus = 200;
        responseBody = '[]';
        await pool.query("DELETE FROM records WHERE kind='feeds' AND id=$1", [feedId]);
      }
    });
    await t.test('OSV connectivity tests use querybatch POST instead of GET', async () => {
      const feedId = 'osv-connectivity-test';
      await put(pool, 'feeds', feedId, {
        id: feedId, name: 'OSV Package Vulnerability Database', type: 'OSV_API',
        url: 'https://api.osv.dev/v1/querybatch', authType: 'NONE',
        enabled: false, rateLimitPerMin: 1, healthStatus: 'UNTESTED',
      });
      try {
        responseBody = JSON.stringify({ results: [{ vulns: [] }] });
        const tested = await post(`/api/feeds/${feedId}/test`);
        assert.equal(tested.status, 200);
        assert.equal(tested.body.success, true);
        assert.equal(capturedUrl, 'https://api.osv.dev/v1/querybatch');
        assert.equal(capturedMethod, 'POST');
        assert.equal(capturedHeaders['content-type'], 'application/json');
        assert.deepEqual(JSON.parse(capturedBody), {
          queries: [{ package: { purl: 'pkg:npm/vulnstream-connectivity-check@1.0.0' } }],
        });
        assert.equal((await get<any>(pool, 'feeds', feedId)).healthStatus, 'HEALTHY');
      } finally {
        responseStatus = 200;
        responseBody = '[]';
        capturedUrl = '';
        capturedUrls = [];
        capturedBody = '';
        capturedMethod = '';
        await pool.query("DELETE FROM records WHERE kind='feeds' AND id=$1", [feedId]);
      }
    });
    await t.test('records persist and feed secrets are encrypted and redacted', async () => {
      assert.equal(
        (
          await command('feed.save', {
            name: 'fixture',
            type: 'JSON_SEARCH_API',
            url: 'https://8.8.8.8/feed',
            authType: 'API_KEY',
            authSecretKey: 'fixture-secret',
            rateLimitPerMin: 10,
            enabled: false,
          })
        ).status,
        200,
      );
      const saved = (await list<any>(pool, 'feeds'))[0];
      assert.notEqual(saved.authSecretKey, 'fixture-secret');
      assert.equal(decrypt(saved.authSecretKey, [key], `feed:${saved.id}`), 'fixture-secret');
      const snapshot = (await admin.get('/api/state')).body;
      assert.equal(snapshot.feeds[0].authSecretKey, undefined);
      const page = await viewer.get('/api/collections/feeds');
      assert.equal(page.status, 200);
      assert.equal(page.body.items[0].authSecretKey, undefined);
      const hidden = await viewer.get('/api/collections/feeds').query({ search: saved.authSecretKey });
      assert.equal(hidden.status, 200);
      assert.equal(hidden.body.total, 0, 'search counts must not reveal stored secrets');
      for (const sort of ['constructor', 'toString', '__proto__']) {
        const sorted = await viewer.get('/api/collections/cveData').query({ sort });
        assert.equal(sorted.status, 200, `prototype property ${sort} must use default sorting`);
      }
      const edit = {
        name: saved.name,
        type: saved.type,
        url: saved.url + '-changed',
        authType: saved.authType,
        rateLimitPerMin: 10,
        enabled: false,
      };
      assert.equal((await command('feed.save', edit, saved.id)).status, 200);
      assert.equal((await get<any>(pool, 'feeds', saved.id)).authSecretKey, '');
      assert.equal(
        (await command('feed.save', { ...edit, authSecretKey: 'fixture-secret' }, saved.id)).status,
        200,
      );

      assert.equal((await supertest(createApp(pool, config, requester)).get('/ready')).status, 200);
    });
    await t.test(
      'pipeline creates a pending advisory and outbox atomically; reruns do not duplicate',
      async () => {
        assert.equal(
          (
            await command('asset.save', {
              vendor: 'example',
              product: 'widget',
              cpes: [cpe('1.0')],
              assetTag: 'asset-one',
              ownerGroup: 'test',
              active: true,
            })
          ).status,
          200,
        );
        assert.equal((await command('cve.save', fixture())).status, 200);
        assert.equal(
          (
            await command('recipient.save', {
              name: 'Recipient',
              email: 'test@example.com',
              role: 'SOC',
              subscriptionTier: 'ALL_SEVERITIES',
              enabled: true,
            })
          ).status,
          200,
        );
        assert.equal((await command('settings.save', { autoDispatchEnabled: true })).status, 200);
        const run = await post('/api/pipeline', {});
        assert.equal(run.status, 202);
        assert.equal(run.body.status, 'QUEUED');
        await processPipeline(pool, config, requester);
        const snapshot = (await admin.get('/api/state')).body;
        assert.equal(snapshot.findings.length, 1);
        assert.equal(snapshot.advisories.length, 1);
        assert.equal(snapshot.advisories[0].deliveryStatus, 'PENDING');
        assert.equal(snapshot.emailLogs[0].status, 'QUEUED');
        assert.equal(snapshot.alertedCves.length, 0);
        await queueRun(pool, 24, 'test');
        await processPipeline(pool, config, requester);
        assert.equal((await pool.query('SELECT count(*)::int AS count FROM outbox')).rows[0].count, 1);
      },
    );
    await t.test(
      'failed transport retries durably, acceptance is recorded without claiming inbox delivery',
      async () => {
        await deliverNext(pool, config, requester, async () => {
          throw Object.assign(new Error('temporary transport outage'), { code: 'ECONNRESET', command: 'CONN' });
        });
        assert.equal((await list<any>(pool, 'emailLogs'))[0].status, 'RETRYING');
        await pool.query("UPDATE outbox SET next_attempt=now() WHERE status='QUEUED'");
        await deliverNext(pool, config, requester, async () => '<provider-message-id>');
        const snapshot = (await admin.get('/api/state')).body;
        assert.equal(snapshot.emailLogs[0].status, 'ACCEPTED');
        assert.equal(snapshot.advisories[0].deliveryStatus, 'ACCEPTED');
        assert.equal(snapshot.alertedCves[0].dispatchCount, 1);
      },
    );
    await t.test('webhook signs timestamp and exact body; nonretryable rejection is terminal', async () => {
      assert.equal(
        (
          await command('webhook.save', {
            name: 'test-hook',
            url: 'https://8.8.8.8/hook',
            provider: 'GENERIC_HMAC',
            secretToken: 'webhook-fixture-secret-at-least-32-characters',
            enabled: true,
            events: ['ALL'],
          })
        ).status,
        200,
      );
      const hook = (await list<WebhookEndpoint>(pool, 'webhooks'))[0];
      assert.notEqual(hook.url, 'https://8.8.8.8/hook');
      const page = await viewer.get('/api/collections/webhooks');
      assert.equal(page.status, 200);
      assert.equal(page.body.items[0].url, '[configured on server]');
      assert.equal(page.body.items[0].secretToken, '');
      for (const search of [hook.url, hook.secretToken]) {
        const hidden = await viewer.get('/api/collections/webhooks').query({ search });
        assert.equal(hidden.status, 200);
        assert.equal(hidden.body.total, 0, 'search counts must not reveal webhook credentials');
      }
      assert.equal((await post(`/api/webhooks/${hook.id}/test`)).status, 202);
      await deliverNext(pool, config, requester, async () => 'unused');
      assert.equal(
        capturedHeaders['x-vulnstream-signature'],
        'sha256=' +
          createHmac('sha256', 'webhook-fixture-secret-at-least-32-characters')
            .update(`${capturedHeaders['x-vulnstream-timestamp']}.${capturedBody}`)
            .digest('hex'),
      );
      responseStatus = 400;
      await post(`/api/webhooks/${hook.id}/test`);
      await deliverNext(pool, config, requester, async () => 'unused');
      assert.equal((await list<any>(pool, 'webhookLogs'))[0].status, 'FAILED');
      responseStatus = 200;
    });
    await t.test('webhook rate limits persist provider cooldown without holding the worker', async () => {
      const hook = (await list<WebhookEndpoint>(pool, 'webhooks'))[0];
      for (const delay of ['1200', new Date(Date.now() + 1800000).toUTCString()]) {
        await post(`/api/webhooks/${hook.id}/test`);
        const before = Date.now();
        await deliverNext(
          pool,
          config,
          async () => ({ status: 429, body: '', headers: { 'retry-after': delay } }),
          async () => 'unused',
        );
        const job = (
          await pool.query(
            "SELECT status,next_attempt FROM outbox WHERE channel='webhook' ORDER BY updated_at DESC LIMIT 1",
          )
        ).rows[0];
        assert.equal(job.status, 'QUEUED');
        assert.ok(new Date(job.next_attempt).getTime() >= before + 1199000);
      }
      const health = (await admin.get('/api/health')).body;
      assert.equal(health.deliveryQueue.dueJobs, 0);
      assert.equal(health.deliveryQueue.oldestDueCreatedAt, null);
      assert.ok(Date.parse(health.deliveryQueue.nextScheduledAttempt) > Date.now());
      assert.equal(health.workerStatus, 'DISABLED');
      // Deferred jobs cannot be claimed by a subsequent idle worker.
      assert.equal(
        await deliverNext(
          pool,
          config,
          async () => {
            throw new Error('Premature retry');
          },
          async () => 'unused',
        ),
        false,
      );
    });
    await t.test('running pipeline recovers after crash and audit is content-verifiable', async () => {
      const queued = await queueRun(pool, 24, 'test');
      await transaction(pool, (db) => put(db, 'executions', queued.id, { ...queued, status: 'RUNNING' }));
      await processPipeline(pool, config, requester);
      assert.equal((await get<any>(pool, 'executions', queued.id)).status, 'COMPLETED');
      const logs = (await admin.get('/api/state')).body.auditLogs;
      assert.equal(verifyAuditChain(logs), true);
      await assert.rejects(
        pool.query('UPDATE audit SET data=data || \'{"event":"tamper"}\'::jsonb'),
        /append-only/,
      );
    });
    await t.test(
      'live adapter data is persisted; feed failure is recorded instead of invented success',
      async () => {
        const feed = (await list<any>(pool, 'feeds'))[0];
        await command('feed.toggle', undefined, feed.id);
        responseBody = JSON.stringify([{ ...fixture(), cveId: 'CVE-2026-23456' }]);
        await queueRun(pool, 24, 'test');
        await processPipeline(pool, config, requester);
        assert.ok(await get(pool, 'cveData', 'CVE-2026-23456'));
        assert.equal((await get<any>(pool, 'feeds', feed.id)).healthStatus, 'HEALTHY');
        responseStatus = 503;
        const failed = await queueRun(pool, 24, 'test');
        await processPipeline(pool, config, requester);
        assert.equal((await get<any>(pool, 'executions', failed.id)).status, 'FAILED');
        assert.equal((await get<any>(pool, 'feeds', feed.id)).healthStatus, 'DOWN');
        responseStatus = 200;
        responseBody = '[]';
        await command('feed.toggle', undefined, feed.id);
      },
    );
    await t.test(
      'disabled recipients prevent queued delivery and concurrent workers claim distinct jobs',
      async () => {
        const recipient = (await list<any>(pool, 'recipients'))[0];
        await command('recipient.toggle', undefined, recipient.id);
        let mailCalls = 0;
        await Promise.all([
          deliverNext(pool, config, requester, async () => {
            mailCalls++;
            return 'unexpected';
          }),
          deliverNext(pool, config, requester, async () => {
            mailCalls++;
            return 'unexpected';
          }),
        ]);
        assert.equal(mailCalls, 0);
      },
    );
    await t.test('password change revokes all sessions; expired sessions fail closed', async () => {
      const changed = await post('/api/password', {
        currentPassword: password,
        newPassword: password + 'changed',
      });
      assert.equal(changed.status, 200);
      assert.equal((await admin.get('/api/state')).status, 401);
      await pool.query("UPDATE sessions SET expires_at=now()-interval '1 second'");
      assert.equal((await viewer.get('/api/state')).status, 401);
    });
    await t.test('self-service password reset via OTP', async () => {
      const resetUser = 'resetter';
      // The reset code is delivered to the account's own address. A username
      // that merely looks like an address must not be used as the mailbox.
      await createUser(pool, resetUser, password, 'OPERATOR', '', 'resetter@example.com');
      const request = (path: string, data: any) =>
        supertest(app).post(path).set('Origin', config.APP_ORIGIN).send(data);
      const requested = await request('/api/password-reset/request', { username: resetUser });
      assert.equal(requested.status, 200);
      assert.equal(requested.body.success, true);
      const devOtp = requested.body.code;
      assert.ok(devOtp, 'OTP should be returned in test/dev mode');
      // An account with no reset address gets no code, and the response is
      // indistinguishable from an unknown account.
      await createUser(pool, 'no-address', password, 'VIEWER');
      const withoutAddress = await request('/api/password-reset/request', { username: 'no-address' });
      assert.equal(withoutAddress.status, 200);
      assert.equal(withoutAddress.body.success, true);
      assert.equal(withoutAddress.body.code, undefined);
      assert.equal((await pool.query("SELECT 1 FROM password_reset_tokens WHERE username='no-address'")).rowCount, 0);
      const nonexistent = await request('/api/password-reset/request', { username: 'does-not-exist' });
      assert.equal(nonexistent.status, 200);
      assert.equal(nonexistent.body.success, true);
      assert.equal(nonexistent.body.code, undefined);
      const verified = await request('/api/password-reset/verify', { username: resetUser, code: devOtp });
      assert.equal(verified.status, 200);
      const badVerify = await request('/api/password-reset/verify', { username: resetUser, code: '000000' });
      assert.equal(badVerify.status, 400);
      const newPassword = 'New-reset-password-2026!';
      const completed = await request('/api/password-reset/complete', {
        username: resetUser,
        code: devOtp,
        newPassword,
      });
      assert.equal(completed.status, 200);
      const stale = await request('/api/password-reset/complete', {
        username: resetUser,
        code: devOtp,
        newPassword,
      });
      assert.equal(stale.status, 400);
      const loginAttempt = await supertest(app)
        .post('/api/login')
        .set('Origin', config.APP_ORIGIN)
        .send({ username: resetUser, password: newPassword });
      assert.equal(loginAttempt.status, 200);
      const expiredOtp = await request('/api/password-reset/verify', { username: resetUser, code: devOtp });
      assert.equal(expiredOtp.status, 400);
      assert.equal(
        (await pool.query('SELECT 1 FROM password_reset_tokens WHERE username=$1', [resetUser])).rows.length,
        0,
      );
    });
    await t.test('session renewal returns 401 when the session is concurrently invalidated', async () => {
      // The preceding password-change scenario deliberately revoked the old
      // session. Establish a fresh one before testing explicit invalidation.
      const freshLogin = await admin.post('/api/login').set('Origin', config.APP_ORIGIN)
        .send({ username: 'admin', password: password + 'changed' });
      assert.equal(freshLogin.status, 200);
      const sessionHash = (await pool.query("SELECT token_hash FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.username='admin'")).rows[0]?.token_hash;
      assert.ok(sessionHash, 'admin should have an active session');
      await pool.query('DELETE FROM sessions WHERE token_hash=$1', [sessionHash]);
      const renewed = await admin
        .post('/api/session/renew')
        .set('Origin', config.APP_ORIGIN)
        .set('x-csrf-token', freshLogin.body.csrfToken)
        .send({});
      assert.equal(renewed.status, 401, 'concurrently invalidated session must yield 401, not a 500 TypeError');
    });
    await t.test('login throttling is stored in PostgreSQL', async () => {
      for (let i = 0; i < 5; i++)
        assert.equal(
          (
            await supertest(app)
              .post('/api/login')
              .set('Origin', config.APP_ORIGIN)
              .send({ username: 'unknown', password: 'wrong' })
          ).status,
          401,
        );
      assert.equal(
        (
          await supertest(app)
            .post('/api/login')
            .set('Origin', config.APP_ORIGIN)
            .send({ username: 'unknown', password: 'wrong' })
        ).status,
        429,
      );
    });
  } finally {
    await pool.end();
    await base.query(`DROP SCHEMA ${schema} CASCADE`);
    await base.end();
  }
});
