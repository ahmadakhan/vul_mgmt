/**
 * Database-backed regressions for the transactional pipeline fixes (H-3, H-4).
 *
 * The pure-function regressions live in pipeline-matching-audit.test.ts; these
 * cases need a real PostgreSQL transaction because they exercise the commit
 * path itself. Both were caught only incidentally by pre-existing lifecycle
 * assertions, so they are pinned here as named findings.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { createPool, migrate, transaction, put, list, get } from '../server/db.ts';
import { queueRun, processPipeline } from '../server/pipeline';
import { loadConfig } from '../server/config.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { NormalizedCVE } from '../src/types/index.ts';

const database = process.env.TEST_DATABASE_URL;
const cpe = (version: string) => `cpe:2.3:a:acme:gateway:${version}:*:*:*:*:*:*:*`;

function vulnerability(): NormalizedCVE {
  return {
    cveId: 'CVE-2026-90001',
    title: 'Pipeline fixture',
    description: 'Test only',
    publishedDate: new Date().toISOString(),
    modifiedDate: new Date().toISOString(),
    cvss: { version: '3.1', score: 8, vector: '', severity: 'HIGH' },
    cwe: [],
    cpeMatches: [cpe('*')],
    cpeMatchDetails: [],
    versionRange: { versionEndExcluding: '2.0' },
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
  } as NormalizedCVE;
}

test('H-3: campaign (KEV) enrichment is persisted even when applicability is unchanged', { skip: !database }, async () => {
  const base = createPool(database!);
  const schema = 'h3_' + randomUUID().replaceAll('-', '');
  await base.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href);
  const config = loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: url.href,
    APP_ORIGIN: 'http://localhost',
    ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  });
  const save = (kind: string, id: string, value: unknown) => transaction(pool, (db) => put(db, kind, id, value));
  try {
    await migrate(pool);
    await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: false });
    await save('feeds', 'kev', {
      id: 'kev',
      name: 'KEV',
      type: 'CISA_KEV',
      url: 'https://example.com/kev',
      authType: 'NONE',
      enabled: true,
      rateLimitPerMin: 60,
    });
    const cve = vulnerability();
    const catalog = JSON.stringify({
      vulnerabilities: [
        {
          cveID: cve.cveId,
          dateAdded: '2026-01-01',
          dueDate: '2026-02-01',
          requiredAction: 'Patch',
          knownRansomwareCampaignUse: 'Unknown',
        },
      ],
    });
    await queueRun(pool, 24, 'test');
    // Respond with an ETag so the next run can legitimately return 304 and be
    // answered from the persisted snapshot.
    await processPipeline(pool, config, async () => ({
      status: 200,
      headers: { etag: '"kev-1"' },
      body: catalog,
    }));

    // The CVE enters the corpus on a later run while KEV is unchanged (304), so
    // all enrichment is driven by the persisted snapshot. Its applicability
    // fields are identical to what the first run stored, so a change detector
    // that only inspects applicability considers it unchanged and drops the KEV
    // enrichment computed for it.
    await save('cveData', cve.cveId, cve);
    await queueRun(pool, 24, 'test');
    await processPipeline(pool, config, async (_, options) => {
      assert.equal(options?.headers?.['If-None-Match'], '"kev-1"');
      return { status: 304, headers: {}, body: '' };
    });

    const stored = await get<NormalizedCVE>(pool, 'cveData', cve.cveId);
    assert.equal(stored?.cisaKev.isKev, true, 'KEV enrichment must reach the persisted record');
    assert.equal(stored?.cisaKev.dateAdded, '2026-01-01');
  } finally {
    await pool.end();
    await base.query(`DROP SCHEMA ${schema} CASCADE`);
    await base.end();
  }
});

test('aborting a stuck pipeline releases its lock and prevents late response persistence', { skip: !database, timeout: 15000 }, async () => {
  const base = createPool(database!);
  const schema = 'abort_' + randomUUID().replaceAll('-', '');
  await base.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href);
  const config = loadConfig({
    NODE_ENV: 'test', DATABASE_URL: url.href, APP_ORIGIN: 'http://localhost',
    ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  });
  const controller = new AbortController();
  let markStarted!: () => void;
  const started = new Promise<void>((resolve) => { markStarted = resolve; });
  let finishRequest!: (response: { status: number; body: string; headers: Record<string, string> }) => void;
  try {
    await migrate(pool);
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: false, schedulerEnabled: false });
    await put(pool, 'feeds', 'stuck', {
      id: 'stuck', name: 'Stuck source', type: 'JSON_SEARCH_API',
      url: 'https://example.com/feed', enabled: true, authType: 'NONE', rateLimitPerMin: 60,
    });
    const queued = await queueRun(pool, 24, 'test');
    const pending = processPipeline(pool, config, async (_url, options) => {
      assert.equal(options?.signal, controller.signal);
      markStarted();
      return new Promise((resolve) => { finishRequest = resolve; });
    }, controller.signal);
    const rejected = assert.rejects(pending, /watchdog cancellation/);
    await started;
    controller.abort(new Error('watchdog cancellation'));
    await rejected;
    assert.equal(await processPipeline(pool, config, async () => ({ status: 200, body: '[]', headers: {} })), true);
    assert.equal((await get<{ status: string }>(pool, 'executions', queued.id))?.status, 'COMPLETED');
    finishRequest({ status: 200, body: JSON.stringify([vulnerability()]), headers: {} });
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal((await list(pool, 'cveData')).length, 0);
    await assert.rejects(processPipeline(pool, config, async () => ({ status: 200, body: '[]', headers: {} }), controller.signal), /watchdog cancellation/);
  } finally {
    controller.abort();
    await pool.end();
    await base.query(`DROP SCHEMA ${schema} CASCADE`);
    await base.end();
  }
});

test('H-4: a lost worker lock requeues the run instead of wedging it in RUNNING', { skip: !database }, async () => {
  const base = createPool(database!);
  const schema = 'h4_' + randomUUID().replaceAll('-', '');
  await base.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href);
  const config = loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: url.href,
    APP_ORIGIN: 'http://localhost',
    ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  });
  const save = (kind: string, id: string, value: unknown) => transaction(pool, (db) => put(db, kind, id, value));
  try {
    await migrate(pool);
    await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: false });
    await save('feeds', 'lock-loss', {
      id: 'lock-loss',
      name: 'Lock loss',
      type: 'JSON_SEARCH_API',
      url: 'https://example.com/feed',
      enabled: true,
      authType: 'NONE',
      rateLimitPerMin: 60,
    });
    const queued = await queueRun(pool, 24, 'test');

    // Kill the advisory-lock backend mid-run. Scope the termination to this
    // schema's lock so concurrently running test schemas are unaffected.
    await assert.rejects(
      processPipeline(pool, config, async () => {
        await pool.query(`SELECT pg_terminate_backend(pid) FROM pg_locks
          WHERE locktype='advisory' AND classid=800003 AND objsubid=2
            AND objid=hashtext(COALESCE(current_schema(), current_database())) AND granted`);
        await new Promise((resolve) => setTimeout(resolve, 50));
        return { status: 200, body: JSON.stringify([vulnerability()]), headers: {} };
      }),
      /lock connection/,
    );

    // The run is handed back, not failed: a FAILED record is skipped by the
    // recovery sweep, which only rescues QUEUED/RUNNING, so failing it here
    // would make the run permanently unrecoverable.
    const afterLoss = await get<{ status: string; logs: string[] }>(pool, 'executions', queued.id);
    assert.equal(afterLoss?.status, 'QUEUED');
    assert.ok(afterLoss?.logs.some((line) => line.includes('lock-connection loss')));

    assert.equal(await processPipeline(pool, config, async () => ({ status: 200, body: '[]', headers: {} })), true);
    const recovered = await get<{ status: string }>(pool, 'executions', queued.id);
    assert.equal(recovered?.status, 'COMPLETED');
    assert.equal((await list(pool, 'cveData')).length, 0, 'the interrupted attempt must not commit partial state');
  } finally {
    await pool.end();
    await base.query(`DROP SCHEMA ${schema} CASCADE`);
    await base.end();
  }
});
