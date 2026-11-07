import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { createPool, migrate, transaction, put, putMany, list, get } from '../server/db.ts';
import { runDailyDigest } from '../server/dailyDigest';
import { resolveTimezone } from '../src/utils/dateTime';
import { queueRun, processPipeline, rebuildFromCurrentInventory, stopRun } from '../server/pipeline';
import { deliverNext, queueAdvisory, queueDigestAdvisory, type Job } from '../server/delivery';
import { flushDueDigest } from '../server/digest';
import { loadConfig } from '../server/config.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { MITRE_DELTA_URL } from '../server/mitre';
import { mitreRecord, mitreDelta } from './fixtures/mitre';
import { applyCommand } from '../server/commands.ts';
import type { Advisory, AliasEntry, Finding, NormalizedCVE, WatchListItem } from '../src/types/index.ts';
import { deriveInventoryAliases } from '../src/utils/aliasLifecycle.ts';
import { registrationAssetsFromCpes } from '../src/utils/watchlist.ts';
import { encrypt } from '../server/secrets.ts';
const database = process.env.TEST_DATABASE_URL;
const cpe = (version: string) => `cpe:2.3:a:example:widget:${version}:*:*:*:*:*:*:*`;
const asset = (version = '1.5'): WatchListItem => ({
  id: 'asset',
  vendor: 'example',
  product: 'widget',
  cpes: [cpe(version)],
  assetTag: 'TEST',
  ownerGroup: 'test',
  active: true,
  createdAt: new Date().toISOString(),
});
const vulnerability = (): NormalizedCVE => ({
  cveId: 'CVE-2026-98001',
  title: 'Lifecycle fixture',
  description: 'Test only',
  publishedDate: new Date().toISOString(),
  modifiedDate: new Date().toISOString(),
  cvss: { version: '3.1', score: 8, vector: '', severity: 'HIGH' },
  cwe: [],
  cpeMatches: [cpe('*')],
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
});
test('pipeline reconciles inventory and protects queued deliveries', { skip: !database }, async (t) => {
  const base = createPool(database!),
    schema = 'lifecycle_' + randomUUID().replaceAll('-', '');
  await base.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(database!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href),
    config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url.href,
      APP_ORIGIN: 'http://localhost',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    });
  const request = async () => {
    throw new Error('No network expected');
  };
  const run = async () => {
    await queueRun(pool, 24, 'test');
    await processPipeline(pool, config, request);
  };
  const save = (kind: string, id: string, value: unknown) =>
    transaction(pool, (db) => put(db, kind, id, value));
  const reset = async () => {
    await pool.query('DELETE FROM records; DELETE FROM outbox');
    await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: false });
  };
  try {
    await migrate(pool);
    await t.test('cached CVE matching uses the queued execution scope, not later settings', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, scopeHours: 1 });
      await save('watchlist', 'asset', asset());
      const cached = vulnerability();
      cached.publishedDate = new Date(Date.now() - 48 * 3600000).toISOString();
      cached.modifiedDate = cached.publishedDate;
      await save('cveData', cached.cveId, cached);
      const execution = await queueRun(pool, 72, 'test');
      assert.equal(execution.scopeHours, 72);
      await processPipeline(pool, config, request);
      const findings = await list<Finding>(pool, 'findings');
      assert.equal(findings.some((finding) => finding.cveId === cached.cveId), true);
    });
    await t.test('incremental checkpoints commit atomically, survive failures, and reset after source changes', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false });
      const source = { id: 'incremental', name: 'NVD incremental', type: 'NVD_API', url: 'https://example.com/nvd', authType: 'NONE', rateLimitPerMin: 600, enabled: true };
      await save('feeds', source.id, source);
      let requestedStart = '', requestedEnd = '';
      const success = async (raw: string) => {
        const url = new URL(raw);
        requestedStart = url.searchParams.get('lastModStartDate')!;
        requestedEnd = url.searchParams.get('lastModEndDate')!;
        return { status: 200, headers: {}, body: JSON.stringify({ startIndex: 0, totalResults: 0, vulnerabilities: [] }) };
      };
      await queueRun(pool, 2880, 'test');
      await processPipeline(pool, config, success);
      assert.ok(Date.parse(requestedEnd) - Date.parse(requestedStart) <= 86400000);
      const first = await get<any>(pool, 'feedCursors', source.id);
      assert.equal(first.cursor, requestedEnd);
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, success);
      assert.equal(Date.parse(requestedStart), Date.parse(first.cursor) - 600000);
      const committed = await get<any>(pool, 'feedCursors', source.id);
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => { throw new Error('Upstream unavailable'); });
      assert.deepEqual(await get(pool, 'feedCursors', source.id), committed);
      await transaction(pool, db => applyCommand(db, config, { action: 'feed.save', id: source.id, data: { ...source, url: 'https://example.com/new-nvd' }, actor: 'test' }));
      await queueRun(pool, 2880, 'test');
      await processPipeline(pool, config, success);
      assert.ok(Date.parse(requestedEnd) - Date.parse(requestedStart) >= 86399000);
      assert.notEqual((await get<any>(pool, 'feedCursors', source.id)).fingerprint, committed.fingerprint);
    });
    await t.test('disabled scheduler leaves catch-up work queued until scheduling is enabled', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false });
      const source = { id: 'catchup', name: 'NVD catch-up', type: 'NVD_API', url: 'https://example.com/nvd', authType: 'NONE', rateLimitPerMin: 600, enabled: true };
      await save('feeds', source.id, source);
      const windows: Array<{ start: number; end: number }> = [];
      const request = async (raw: string) => {
        const url = new URL(raw);
        windows.push({
          start: Date.parse(url.searchParams.get('lastModStartDate')!),
          end: Date.parse(url.searchParams.get('lastModEndDate')!),
        });
        return { status: 200, headers: {}, body: JSON.stringify({ startIndex: 0, totalResults: 0, vulnerabilities: [] }) };
      };
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, request);
      const cursor = await get<any>(pool, 'feedCursors', source.id);
      const old = Date.now() - 72 * 3600000;
      await save('feedCursors', source.id, { ...cursor, cursor: new Date(old).toISOString(), hasMore: true });
      assert.equal(await processPipeline(pool, config, request), false);
      assert.equal((await get<any>(pool, 'feedCursors', source.id)).cursor, new Date(old).toISOString());
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: true });
      windows.length = 0;
      assert.equal(await processPipeline(pool, config, request), true);
      // A single run may consume several consecutive catch-up windows, but each
      // individual provider request must remain bounded to one day.
      assert.ok(windows.length > 0);
      for (const window of windows) assert.ok(window.end - window.start <= 86400000);
      const next = await get<any>(pool, 'feedCursors', source.id);
      assert.ok(Date.parse(next.cursor) > old);
      assert.ok(Date.parse(next.cursor) >= Date.now() - 60000);
      assert.equal(next.hasMore, false);
      await save('feeds', source.id, { ...source, enabled: false });
      assert.equal(await processPipeline(pool, config, request), false);
    });
    await t.test('catch-up cooldown blocks immediate re-run after a partial catch-up', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: true, schedulerIntervalMinutes: 60 });
      const source = { id: 'catchup-cd', name: 'NVD cooldown', type: 'NVD_API', url: 'https://example.com/nvd', authType: 'NONE', rateLimitPerMin: 600, enabled: true };
      await save('feeds', source.id, source);
      // First run to establish a cursor with the correct fingerprint.
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => ({ status: 200, headers: {}, body: JSON.stringify({ startIndex: 0, totalResults: 0, vulnerabilities: [] }) }));
      const cursor = await get<any>(pool, 'feedCursors', source.id);
      // Simulate a partial catch-up: hasMore true, catch_up true, next_catchup_at in the future.
      const futureCooldown = new Date(Date.now() + 60000).toISOString();
      const oldCursor = new Date(Date.now() - 72 * 3600000).toISOString();
      await save('feedCursors', source.id, { ...cursor, cursor: oldCursor, hasMore: true, catch_up: true, next_catchup_at: futureCooldown });
      // Set scheduler_state: last_run recent so interval check fails, next_catchup_run NULL.
      await pool.query('UPDATE scheduler_state SET last_run=$1, next_catchup_run=NULL WHERE id=1', [new Date(Date.now() - 30000).toISOString()]);
      const noOp = async () => { throw new Error('should not reach network'); };
      // Cooldown not elapsed → should not start (hasMore no longer bypasses the cooldown).
      assert.equal(await processPipeline(pool, config, noOp), false);
      const unchanged = await get<any>(pool, 'feedCursors', source.id);
      assert.equal(unchanged.cursor, oldCursor);
      assert.equal(unchanged.hasMore, true);
      assert.equal(unchanged.catch_up, true);
      // Advance cooldown to the past.
      await save('feedCursors', source.id, { ...cursor, cursor: oldCursor, hasMore: true, catch_up: true, next_catchup_at: new Date(Date.now() - 1000).toISOString() });
      // Cooldown elapsed → should start.
      assert.equal(
        await processPipeline(pool, config, async () => ({ status: 200, headers: {}, body: JSON.stringify({ startIndex: 0, totalResults: 0, vulnerabilities: [] }) })),
        true,
      );
    });
    await t.test('MITRE CVE and overlapping feeds persist one CVE and stable inventory findings across runs', async () => {
      await reset();
      await save('watchlist', 'asset', asset());
      const date = new Date(Date.now() - 1000).toISOString();
      const common = { authType: 'NONE', enabled: true, rateLimitPerMin: 600 };
      await save('feeds', 'mitre', { ...common, id: 'mitre', name: 'MITRE CVE', type: 'MITRE_CVE', url: MITRE_DELTA_URL });
      await save('feeds', 'nvd', { ...common, id: 'nvd', name: 'NVD', type: 'NVD_API', url: 'https://example.com/nvd' });
      const sourceRequest = async (url: string) => {
        const data = url === MITRE_DELTA_URL ? mitreDelta(undefined, date)
          : url.startsWith('https://raw.githubusercontent.com/') ? mitreRecord(undefined, date)
          : { startIndex: 0, totalResults: 1, vulnerabilities: [{ cve: {
              id: 'CVE-2026-98001', published: date, lastModified: date, vulnStatus: 'Analyzed',
              descriptions: [{ lang: 'en', value: 'Example widget vulnerability' }],
              configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: cpe('*') }] }] }],
            } }] };
        return { status: 200, body: JSON.stringify(data), headers: {} };
      };
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, sourceRequest);
      const cves = await list<NormalizedCVE>(pool, 'cveData');
      assert.equal(cves.length, 1);
      assert.deepEqual(cves[0].sourceFeeds, ['mitre', 'nvd']);
      const first = await list<Finding>(pool, 'findings');
      assert.equal(first.length, 1);
      assert.equal(
        (await list<any>(pool, 'executions'))[0].stats.matchedWatchlist,
        1,
        'the detecting run reports the new finding',
      );
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, sourceRequest);
      assert.equal((await list(pool, 'cveData')).length, 1);
      const second = await list<Finding>(pool, 'findings');
      assert.equal(second.length, 1);
      assert.equal(second[0].id, first[0].id);
      // A repeat run re-derives every current match to refresh applicability; it
      // must not report that whole corpus as newly detected.
      assert.equal(
        (await list<any>(pool, 'executions'))[0].stats.matchedWatchlist,
        0,
        'a run that only refreshes existing matches detects nothing new',
      );
      assert.equal((await get<any>(pool, 'feeds', 'mitre')).healthStatus, 'HEALTHY');
    });
    await t.test('configured advisory prefix reaches queued email subjects and bodies automatically', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, advisoryPrefix: 'SECURITY-', autoDispatchEnabled: true });
      await save('watchlist', 'asset', asset());
      await save('cveData', vulnerability().cveId, vulnerability());
      await save('recipients', 'rec', { id: 'rec', name: 'Test', email: 'test@example.invalid', enabled: true, subscriptionTier: 'ALL_SEVERITIES' });
      await run();
      const jobs = (await pool.query('SELECT payload,advisory_id FROM outbox')).rows;
      assert.equal(jobs.length, 1);
      assert.match(jobs[0].advisory_id, /^SECURITY-/);
      assert.ok(jobs[0].payload.subject.startsWith(`[${jobs[0].advisory_id}] [HIGH]`));
      assert.ok(jobs[0].payload.text.includes(`Advisory ID: ${jobs[0].advisory_id}`));
      assert.ok(jobs[0].payload.html.includes(jobs[0].advisory_id));
    });
    await t.test('timed out source recovers without the scheduler being enabled', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false, autoDispatchEnabled: false });
      await save('feeds', 'recover-feed', {
        id: 'recover-feed', name: 'Recovery test', type: 'JSON_SEARCH_API',
        url: 'https://example.com/feed', enabled: true, authType: 'NONE',
        rateLimitPerMin: 60, recoveryDelayMinutes: 1,
      });
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => { throw new Error('Outbound request timed out'); });
      const failed = await get<any>(pool, 'feeds', 'recover-feed');
      assert.equal(failed.healthStatus, 'DOWN');
      assert.ok(Date.parse(failed.circuitOpenUntil) > Date.now());
      assert.equal(await processPipeline(pool, config, request), false);
      await save('feeds', failed.id, { ...failed, circuitOpenUntil: new Date(Date.now() - 1000).toISOString(), lastRecoveryAttemptAt: new Date(Date.now() - 60000).toISOString() });
      assert.equal(await processPipeline(pool, config, async () => ({ status: 200, body: '[]', headers: {} })), true);
      const recovered = await get<any>(pool, 'feeds', failed.id);
      assert.equal(recovered.healthStatus, 'HEALTHY');
      assert.equal(recovered.consecutiveFailures, 0);
      assert.equal(recovered.circuitOpenUntil, null);
    });
    await t.test('DOWN feed with no circuit deadline auto-recovers with scheduler disabled', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false });
      await save('feeds', 'no-circuit', {
        id: 'no-circuit', name: 'No circuit feed', type: 'JSON_SEARCH_API',
        url: 'https://example.com/feed', enabled: true, authType: 'NONE',
        rateLimitPerMin: 60, healthStatus: 'DOWN', recoveryDelayMinutes: 1,
      });
      let calls = 0;
      const success = async () => {
        calls++;
        return { status: 200, body: '[]', headers: {} };
      };
      assert.equal(await processPipeline(pool, config, success), true);
      const recovered = await get<any>(pool, 'feeds', 'no-circuit');
      assert.equal(calls, 1);
      assert.equal(recovered.healthStatus, 'HEALTHY');
      assert.equal(recovered.consecutiveFailures, 0);
      assert.equal(recovered.circuitOpenUntil, null);
    });
    await t.test('concurrent queue requests create one execution and one worker owns ingestion', async () => {
      await reset();
      const queued = await Promise.all(Array.from({ length: 8 }, () => queueRun(pool, 24, 'test')));
      assert.equal(new Set(queued.map(run => run.id)).size, 1);
      await save('feeds', 'single-worker', {
        id: 'single-worker', name: 'Single worker', type: 'JSON_SEARCH_API', url: 'https://example.com/feed',
        enabled: true, authType: 'NONE', rateLimitPerMin: 60,
      });
      let calls = 0;
      await Promise.all(Array.from({ length: 3 }, () => processPipeline(pool, config, async () => {
        calls++;
        await new Promise(resolve => setTimeout(resolve, 50));
        return { status: 200, body: '[]', headers: {} };
      })));
      assert.equal(calls, 1);
    });
    await t.test('EPSS without applicable inventory clears overdue recovery instead of repeatedly queuing', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false });
      await save('feeds', 'empty-epss', {
        id: 'empty-epss', name: 'EPSS', type: 'EPSS_API', url: 'https://example.com/epss',
        enabled: true, authType: 'NONE', rateLimitPerMin: 60, healthStatus: 'DOWN',
        consecutiveFailures: 1, circuitOpenUntil: new Date(Date.now() - 1000).toISOString(),
      });
      assert.equal(await processPipeline(pool, config, request), true);
      const source = await get<any>(pool, 'feeds', 'empty-epss');
      assert.equal(source.circuitOpenUntil, null);
      assert.equal(source.consecutiveFailures, 0);
      assert.equal(source.healthStatus, 'UNTESTED');
      assert.equal(await processPipeline(pool, config, request), false);
    });
    await t.test('source duration budget discards late responses and schedules recovery', async () => {
      await reset();
      await save('feeds', 'slow-feed', {
        id: 'slow-feed', name: 'Slow source', type: 'JSON_SEARCH_API', url: 'https://example.com/feed',
        enabled: true, authType: 'NONE', rateLimitPerMin: 60,
      });
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, { ...config, FEED_MAX_DURATION_SECONDS: 1 }, async (_url, options) => {
        assert.ok(options!.timeoutMs! <= 1000);
        await new Promise(resolve => setTimeout(resolve, 1100));
        return { status: 200, body: JSON.stringify([vulnerability()]), headers: {} };
      });
      const source = await get<any>(pool, 'feeds', 'slow-feed');
      // Audit R-2: a duration overrun is a capacity signal for THIS run, not
      // proof the source is unreachable. It is reported as DEGRADED and must
      // not consume the failure budget or open the breaker; otherwise three
      // slow-but-healthy bootstraps circuit-break a working source and suppress
      // the catch-up it still owes. A transient transport failure still counts.
      assert.equal(source.healthStatus, 'DEGRADED');
      assert.match(source.errorLog, /duration limit/);
      assert.equal((await list(pool, 'cveData')).length, 0);
      assert.equal(source.consecutiveFailures, 0, 'deadline is not a failure');
      assert.equal(source.circuitOpenUntil, null, 'deadline must not open the breaker');
    });
    await t.test('lost worker lock prevents commit and the next worker recovers the run', async () => {
      await reset();
      await save('feeds', 'lock-loss', {
        id: 'lock-loss', name: 'Lock loss', type: 'JSON_SEARCH_API', url: 'https://example.com/feed',
        enabled: true, authType: 'NONE', rateLimitPerMin: 60,
      });
      const queued = await queueRun(pool, 24, 'test');
      await assert.rejects(processPipeline(pool, config, async () => {
        // Two-int advisory locks are exposed as classid/objid in pg_locks;
        // scope the termination to this schema so parallel test databases and
        // other deployments sharing the cluster are not affected.
        await pool.query(`SELECT pg_terminate_backend(pid) FROM pg_locks
          WHERE locktype='advisory' AND classid=800003 AND objsubid=2
            AND objid=hashtext(COALESCE(current_schema(), current_database())) AND granted`);
        await new Promise(resolve => setTimeout(resolve, 50));
        return { status: 200, body: JSON.stringify([vulnerability()]), headers: {} };
      }), /lock connection/);
      assert.equal((await list(pool, 'cveData')).length, 0);
      assert.equal(await processPipeline(pool, config, async () => ({ status: 200, body: '[]', headers: {} })), true);
      const recovered = await get<any>(pool, 'executions', queued.id);
      assert.equal(recovered.status, 'COMPLETED');
      assert.ok(recovered.logs.some((line: string) => line.includes('Recovered interrupted worker')));
    });
    await t.test('queued stop is idempotent and never runs', async () => {
      await reset();
      const queued = await queueRun(pool, 24, 'test');
      assert.equal((await stopRun(pool, queued.id, 'test')).status, 'CANCELLED');
      assert.equal((await stopRun(pool, queued.id, 'test')).status, 'CANCELLED');
      assert.equal(await processPipeline(pool, config, request), false);
    });
    await t.test('stop during network retrieval discards results and releases worker lock', async () => {
      await reset();
      await save('feeds', 'stop-feed', {
        id: 'stop-feed',
        name: 'Stop test',
        type: 'JSON_SEARCH_API',
        url: 'https://example.com/feed',
        enabled: true,
        authType: 'NONE',
        rateLimitPerMin: 60,
      });
      const queued = await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => {
        const live = await get<any>(pool, 'executions', queued.id);
        assert.equal(live.phases[0].status, 'RUNNING');
        assert.equal(live.phases[1].status, 'PENDING');
        await stopRun(pool, queued.id, 'test');
        return { status: 200, body: JSON.stringify([vulnerability()]), headers: {} };
      });
      const stopped = await get<any>(pool, 'executions', queued.id);
      assert.equal(stopped.status, 'CANCELLED');
      assert.ok(stopped.stopRequestedAt);
      assert.equal(await get(pool, 'feedCursors', 'stop-feed'), undefined);
      assert.equal((await list(pool, 'cveData')).length, 0);
      assert.equal((await list(pool, 'findings')).length, 0);
      assert.equal((await pool.query('SELECT count(*) FROM outbox')).rows[0].count, '0');
      await save('feeds', 'stop-feed', { id: 'stop-feed', enabled: false });
      await run();
      assert.ok((await list<any>(pool, 'executions')).some((e) => e.status === 'COMPLETED'));
    });
    await t.test('large bulk writes stay below parameter limits and preserve unchanged rows', async () => {
      await reset();
      const rows = Array.from({ length: 22000 }, (_, id) => ({ id: String(id), data: { value: id } }));
      await transaction(pool, (db) => putMany(db, 'bulk-test', [...rows, { id: '0', data: { value: -1 } }]));
      assert.equal(
        (await pool.query("SELECT count(*)::int AS n FROM records WHERE kind='bulk-test'")).rows[0].n,
        22000,
      );
      assert.deepEqual(await get(pool, 'bulk-test', '0'), { value: -1 });
      await pool.query("UPDATE records SET updated_at='2000-01-01T00:00:00Z' WHERE kind='bulk-test' AND id='0'");
      await transaction(pool, (db) => putMany(db, 'bulk-test', [{ id: '0', data: { value: -1 } }]));
      assert.equal(
        (
          await pool.query("SELECT updated_at FROM records WHERE kind='bulk-test' AND id='0'")
        ).rows[0].updated_at.toISOString(),
        '2000-01-01T00:00:00.000Z',
      );
    });
    await t.test('new inventory is matched against older cached CVEs', async () => {
      await reset();
      const cve = vulnerability();
      cve.publishedDate = cve.modifiedDate = '2020-01-01T00:00:00Z';
      await save('cveData', cve.cveId, cve);
      await save('watchlist', 'asset', asset());
      await run();
      assert.equal((await list(pool, 'findings')).length, 1);
      const older = { ...cve, cveId: 'CVE-2020-98002' };
      await save('cveData', older.cveId, older);
      await run();
      const retained = await list<Finding>(pool, 'findings');
      assert.equal(retained.length, 1, 'unchanged inventory must not discover unrelated historical CVEs');
      assert.notEqual(retained[0].notificationStatus, 'NOT_APPLICABLE', 'age alone must not invalidate an existing match');
      await save('watchlist', 'asset', asset('1.4'));
      await run();
      assert.equal((await list(pool, 'findings')).length, 2, 'changed inventory must rematch the historical cache once');
    });
    await t.test('repeated bulk inventory imports preserve asset and finding identities', async () => {
      await reset();
      const { id: _id, createdAt: _created, ...item } = asset();
      const importItems = () =>
        transaction(pool, (db) =>
          applyCommand(db, config, { action: 'asset.import', data: [item, item], actor: 'test' }),
        );
      assert.equal((await importItems()).imported, 1);
      const first = (await list<WatchListItem>(pool, 'watchlist'))[0];
      await save('cveData', vulnerability().cveId, vulnerability());
      await run();
      const finding = (await list<Finding>(pool, 'findings'))[0];
      await importItems();
      await run();
      assert.equal((await list<WatchListItem>(pool, 'watchlist')).length, 1);
      assert.equal((await list<WatchListItem>(pool, 'watchlist'))[0].id, first.id);
      assert.equal((await list<Finding>(pool, 'findings')).length, 1);
      assert.equal((await list<Finding>(pool, 'findings'))[0].id, finding.id);
    });
    await t.test('review findings promote after inventory correction and retain stable IDs', async () => {
      await reset();
      const cve = vulnerability();
      await save('cveData', cve.cveId, cve);
      await save('watchlist', 'asset', asset('1.*'));
      await run();
      const first = (await list<Finding>(pool, 'findings'))[0];
      assert.equal(first.notificationStatus, 'REVIEW_REQUIRED');
      await save('watchlist', 'asset', asset());
      await run();
      const next = (await list<Finding>(pool, 'findings'))[0];
      assert.equal(next.id, first.id);
      assert.equal(next.notificationStatus, 'QUEUED_FOR_DISPATCH');
      await save('findings', next.id, { ...next, status: 'FALSE_POSITIVE' });
      await run();
      assert.equal((await list(pool, 'findings')).length, 1);
      assert.equal((await get<Finding>(pool, 'findings', next.id))?.status, 'FALSE_POSITIVE');
    });
    await t.test('patched or removed inventory cannot retain pending applicability', async () => {
      await reset();
      const cve = vulnerability();
      await save('cveData', cve.cveId, cve);
      await save('watchlist', 'asset', asset());
      await run();
      await save('watchlist', 'asset', asset('2.0'));
      await run();
      assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'NOT_APPLICABLE');
      await save('watchlist', 'asset', asset());
      await run();
      assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'QUEUED_FOR_DISPATCH');
      await pool.query("DELETE FROM records WHERE kind='watchlist'");
      await run();
      assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'NOT_APPLICABLE');
    });
    await t.test('changed CVE applicability and enrichment refresh existing findings', async () => {
      await reset();
      const cve = vulnerability();
      await save('cveData', cve.cveId, cve);
      await save('watchlist', 'asset', asset());
      await run();
      await save('cveData', cve.cveId, {
        ...cve,
        applicabilityRequiresReview: true,
        epss: { score: 0.9, percentile: 0.99 },
      });
      await run();
      const finding = (await list<Finding>(pool, 'findings'))[0];
      assert.equal(finding.notificationStatus, 'REVIEW_REQUIRED');
      assert.equal(finding.cve.epss.score, 0.9);
    });
    await t.test('delivery honors the saved confidence policy for email and webhooks', async () => {
      for (const tightenPolicy of [false, true]) {
        await reset();
        // 80% keeps the 85% alias correlation dispatchable; the tightened 90% run
        // below is the policy change this scenario exercises.
        await save('settings', 'main', {
          ...DEFAULT_SETTINGS, autoDispatchEnabled: true, autoDispatchConfidenceThreshold: 80,
        });
        // The asset declares its version explicitly. Without it a version-bound
        // advisory can only be a review candidate, never a confirmed match.
        await save('watchlist', 'asset', {
          ...asset(), version: '1.5', vendor: 'example_alias',
          cpes: [cpe('1.5').replace(':example:', ':example_alias:')],
        });
        await save('aliases', 'vendor-alias', {
          id: 'vendor-alias', scope: 'VENDOR', canonical: 'example', aliases: ['example_alias'],
          source: 'MANUAL', createdAt: new Date().toISOString(),
        });
        await save('cveData', vulnerability().cveId, vulnerability());
        await save('recipients', 'recipient', {
          id: 'recipient', name: 'test', email: 'test@example.invalid', enabled: true,
          subscriptionTier: 'ALL_SEVERITIES',
        });
        await save('webhooks', 'hook', {
          id: 'hook', name: 'test', provider: 'GENERIC_HMAC', enabled: true, events: ['ALL'],
          url: encrypt('https://example.com/hook', [config.ENCRYPTION_KEY], 'webhook-url:hook'),
          secretToken: encrypt('test-secret', [config.ENCRYPTION_KEY], 'webhook:hook'), deliveryCount: 0,
        });
        await run();
        const finding = (await list<Finding>(pool, 'findings'))[0];
        assert.equal(finding.matchingMethod, 'VENDOR_PRODUCT_ALIAS');
        assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH', finding.matchingEvidence);
        assert.equal((await pool.query('SELECT count(*)::int AS n FROM outbox')).rows[0].n, 2, JSON.stringify((await pool.query('SELECT payload FROM outbox')).rows));
        if (tightenPolicy)
          await save('settings', 'main', {
            // Above the 85% alias correlation, so the queued finding is now held.
            ...DEFAULT_SETTINGS, autoDispatchEnabled: true, autoDispatchConfidenceThreshold: 87,
          });
        let emails = 0, webhooks = 0;
        const webhookRequest = async () => {
          webhooks++;
          return { status: 200, body: '', headers: {} };
        };
        const mail = async () => { emails++; return 'accepted-current-policy'; };
        while (await deliverNext(pool, config, webhookRequest, mail)) { /* Mock transports only. */ }
        assert.equal(emails, tightenPolicy ? 0 : 1);
        assert.equal(webhooks, tightenPolicy ? 0 : 1);
        const jobs = (
          await pool.query('SELECT status, channel, error FROM outbox ORDER BY channel')
        ).rows;
        assert.equal(jobs.length, 2, JSON.stringify(jobs));
        // A policy-driven hold is not an applicability change: the finding is
        // still a real match, so the email waits for operator review instead of
        // being dropped, and the webhook job is refused as before. If every job in
        // the bundle is held there is nothing to regroup, so the bundle is failed
        // as a whole and recovery does not schedule a rebuild.
        assert.ok(
          jobs.every(job =>
            tightenPolicy
              ? job.channel === 'email' ? ['REVIEW', 'FAILED'].includes(job.status) : job.status === 'FAILED'
              : job.status === 'ACCEPTED',
          ),
          JSON.stringify(jobs),
        );
        if (tightenPolicy) {
          assert.ok(
            jobs.every(job =>
              job.channel === 'email'
                ? /requires review/.test(job.error)
                : /confidence policy requires review/.test(job.error),
            ),
            JSON.stringify(jobs),
          );
          // Recovery is debounced by staleAdvisoryReason (it only rebuilds once per
          // reason), so drive the next scheduled run.
          await transaction(pool, (db) =>
            db.query("DELETE FROM records WHERE kind='systemState' AND id='pipeline-recovery-reason'"),
          );
          // An operator releases the finding without automatic dispatch. The
          // webhook job that was failed as stale is not resurrected automatically.
          await save('settings', 'main', {
            ...DEFAULT_SETTINGS, autoDispatchEnabled: false, autoDispatchConfidenceThreshold: 80,
          });
          await transaction(pool, (db) =>
            db.query("UPDATE records SET data=data-'advisoryId'-'autoDispatchedAt' WHERE kind='findings'"),
          );
          await run();
          assert.equal((await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='QUEUED'")).rows[0].n, 0, 'automatic dispatch is disabled');
          // Explicit operator approval releases the held email after the policy
          // permits it. It does not resurrect the failed webhook.
          await pool.query("UPDATE outbox SET status='QUEUED', review_approved=true, attempts=0, next_attempt=now(), error=NULL WHERE status='REVIEW' AND channel='email'");
          const requeued = (await pool.query("SELECT channel, payload FROM outbox WHERE status='QUEUED'")).rows;
          assert.equal(requeued.length, 1, JSON.stringify(requeued.map((row) => [row.channel, row.payload?.includedFindingIds])));
          assert.equal(requeued[0].channel, 'email');
          while (await deliverNext(pool, config, webhookRequest, mail)) { /* Rebuilt, revalidated jobs only. */ }
          assert.equal(emails, 1, JSON.stringify((await pool.query('SELECT channel,status,error FROM outbox')).rows));
          assert.equal(webhooks, 0);
          await run();
          assert.equal((await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='QUEUED'")).rows[0].n, 0);
        }
      }
    });
    await t.test('all-version and exact SonicWall CPEs both queue email delivery', async () => {
      await reset();
      await save('settings', 'main', {
        ...DEFAULT_SETTINGS,
        autoDispatchEnabled: true,
        autoDispatchConfidenceThreshold: 90,
        digestBatchingEnabled: false,
      });
      await save('recipients', 'sonicwall-recipient', {
        id: 'sonicwall-recipient',
        name: 'SonicWall test recipient',
        email: 'sonicwall@example.invalid',
        enabled: true,
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'ALL_SEVERITIES',
      });
      const product = 'cpe:2.3:a:sonicwall:network_security_manager';
      const affected = `${product}:4.3.1:*:*:*:*:*:*:*`;
      await save('watchlist', 'sonicwall-all', {
        ...asset('*'),
        id: 'sonicwall-all',
        assetTag: 'SW-ALL',
        vendor: 'sonicwall',
        product: 'network_security_manager',
        version: '*',
        cpes: [`${product}:*:*:*:*:*:*:*:*`],
      });
      await save('watchlist', 'sonicwall-exact', {
        ...asset('4.3.1'),
        id: 'sonicwall-exact',
        assetTag: 'SW-4.3.1',
        vendor: 'sonicwall',
        product: 'network_security_manager',
        version: '4.3.1',
        cpes: [affected],
      });
      await save('cveData', 'CVE-2026-98002', {
        ...vulnerability(),
        cveId: 'CVE-2026-98002',
        cpeMatches: [affected],
        versionRange: undefined,
      });

      await run();

      const findings = await list<Finding>(pool, 'findings');
      assert.equal(findings.length, 2);
      assert.ok(findings.every((finding) => finding.notificationStatus === 'QUEUED_FOR_DISPATCH'));
      const advisories = await list<Advisory>(pool, 'advisories');
      assert.equal(advisories.length, 1);
      assert.deepEqual(new Set(advisories[0].findingIds), new Set(findings.map((finding) => finding.id)));
      const jobs = await pool.query<{ status: string; advisory_id: string }>(
        "SELECT status, advisory_id FROM outbox WHERE channel='email'",
      );
      assert.equal(jobs.rows.length, 1);
      assert.equal(jobs.rows[0].status, 'QUEUED');
      assert.equal(jobs.rows[0].advisory_id, advisories[0].id);
    });
    await t.test('SonicOS KEV text evidence queues email for a registered all-version product', async () => {
      await reset();
      await save('settings', 'main', {
        ...DEFAULT_SETTINGS,
        autoDispatchEnabled: true,
        autoDispatchConfidenceThreshold: 90,
        digestBatchingEnabled: false,
      });
      await save('recipients', 'sonicwall-kev-recipient', {
        id: 'sonicwall-kev-recipient',
        name: 'SonicWall test recipient',
        email: 'sonicwall-kev@example.invalid',
        enabled: true,
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'ALL_SEVERITIES',
      });
      const [registered] = registrationAssetsFromCpes(
        ['cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*'],
        { assetTag: 'SW-SONICOS', ownerGroup: 'SOC', notes: '', purls: [] },
      );
      await save('watchlist', 'sonicwall-sonicos', {
        ...registered,
        id: 'sonicwall-sonicos',
        createdAt: new Date().toISOString(),
      });
      await save('cveData', 'CVE-2026-19868', {
        ...vulnerability(),
        cveId: 'CVE-2026-19868',
        title: 'SonicOS SSLVPN authentication enforcement vulnerability',
        description: 'An authentication enforcement vulnerability affects the SonicOS SSLVPN service.',
        cpeMatches: [],
        cpeMatchDetails: [],
        versionRange: undefined,
        purls: undefined,
        applicabilityRequiresReview: true,
        applicabilityPolicy: 'REVIEW_ONLY',
        cisaKev: { isKev: true, dateAdded: '2026-11-06' },
      });

      await run();

      const finding = (await list<Finding>(pool, 'findings'))[0];
      assert.equal(finding.notificationStatus, 'QUEUED_FOR_DISPATCH');
      const jobs = await pool.query<{ status: string }>(
        "SELECT status FROM outbox WHERE channel='email' AND target_id='sonicwall-kev-recipient'",
      );
      assert.equal(jobs.rows.length, 1);
      assert.equal(jobs.rows[0].status, 'QUEUED');
    });
    await t.test(
      'delivery rechecks current inventory before sending an already queued advisory',
      async () => {
        await reset();
        await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
        await save('recipients', 'recipient', {
          id: 'recipient',
          name: 'test',
          email: 'test@example.invalid',
          role: 'test',
          subscriptionTier: 'ALL_SEVERITIES',
          enabled: true,
          deliverySuccessRate: 0,
        });
        const cve = vulnerability();
        await save('cveData', cve.cveId, cve);
        await save('watchlist', 'asset', asset());
        await save('watchlist', 'asset-2', {
          ...asset(),
          id: 'asset-2',
          assetTag: 'TEST-SECOND',
        });
        await run();
        assert.equal(
          (await pool.query("SELECT count(*)::int AS count FROM outbox WHERE status='QUEUED'")).rows[0].count,
          1,
        );
        const execution = (await list<any>(pool, 'executions'))[0];
        assert.equal(execution.scopeHours, 24);
        assert.equal(execution.stats.notificationsQueued, 1);
        assert.equal(execution.stats.advisoriesQueued, 1);
        assert.deepEqual(
          execution.phases.map((phase: any) => phase.name),
          ['Feed ingestion', 'Normalize & deduplicate', 'Product matching', 'Delivery queue'],
        );
        await save('watchlist', 'asset', asset('2.0'));
        let calls = 0;
        await deliverNext(pool, config, request, async () => {
          calls++;
          return 'must-not-send';
        });
        assert.equal(calls, 0);
        assert.equal((await pool.query('SELECT status FROM outbox')).rows[0].status, 'FAILED');
        // A wholly blocked, never-accepted bundle can be rebuilt once applicable again.
        await save('watchlist', 'asset', asset());
        await run();
        const pendingJobs = (await pool.query(`SELECT COALESCE(o.payload->'includedFindingIds', a.data->'findingIds') AS ids FROM outbox o JOIN records a ON a.kind='advisories' AND a.id=o.advisory_id WHERE o.status='QUEUED'`)).rows;
        const ids = pendingJobs.flatMap(row => row.ids);
        assert.equal(ids.length, 2, 'both currently affected assets must be delivered');
        assert.equal(new Set(ids).size, 2, 'a rebuilt finding must not be queued twice');
        while (await deliverNext(pool, config, request, async () => {
          calls++;
          return 'accepted-current';
        })) { /* Drain only mock transports. */ }
        assert.equal(calls, pendingJobs.length);
        await run();
        assert.equal(
          (await pool.query("SELECT count(*)::int AS count FROM outbox WHERE status='QUEUED'")).rows[0].count,
          0,
        );
      },
    );
    await t.test(
      'retention of the threat cache does not permanently block a queued advisory',
      async () => {
        await reset();
        await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
        await save('recipients', 'recipient', {
          id: 'recipient',
          name: 'test',
          email: 'test@example.invalid',
          role: 'test',
          subscriptionTier: 'ALL_SEVERITIES',
          enabled: true,
          deliverySuccessRate: 0,
        });
        const cve = vulnerability();
        await save('cveData', cve.cveId, cve);
        await save('watchlist', 'asset', asset());
        await run();
        assert.equal(
          (await pool.query("SELECT count(*)::int AS count FROM outbox WHERE status='QUEUED'")).rows[0]
            .count,
          1,
        );
        // The retention policy may remove the regenerable cache record while a
        // manually reviewed advisory is still waiting to be delivered.
        await pool.query("DELETE FROM records WHERE kind='cveData' AND id=$1", [cve.cveId]);
        let calls = 0;
        await deliverNext(pool, config, request, async () => {
          calls++;
          return 'accepted-from-finding-snapshot';
        });
        assert.equal(calls, 1);
        assert.equal((await pool.query('SELECT status FROM outbox')).rows[0].status, 'ACCEPTED');
      },
    );
    await t.test('feed circuit breaker cools down and allows a recovery probe', async () => {
      await reset();
      await save('feeds', 'cooling-feed', {
        id: 'cooling-feed',
        name: 'Cooling test feed',
        type: 'JSON_SEARCH_API',
        url: 'https://8.8.8.8/feed',
        authType: 'NONE',
        rateLimitPerMin: 60,
        enabled: true,
        healthStatus: 'DOWN',
        lastSync: null,
        latencyMs: 0,
        vendorSeed: false,
        itemCountLastRun: 0,
        ssrfValidated: false,
        consecutiveFailures: 5,
        circuitOpenUntil: new Date(Date.now() + 60_000).toISOString(),
      });
      let calls = 0;
      const probe = async () => {
        calls++;
        return { status: 200, body: '[]', headers: {} };
      };
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, probe);
      assert.equal(calls, 0);
      assert.equal((await get<any>(pool, 'feeds', 'cooling-feed')).consecutiveFailures, 5);

      await save('feeds', 'cooling-feed', {
        ...(await get<any>(pool, 'feeds', 'cooling-feed')),
        circuitOpenUntil: new Date(Date.now() - 1000).toISOString(),
      });
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, probe);
      const recovered = await get<any>(pool, 'feeds', 'cooling-feed');
      assert.equal(calls, 1);
      assert.equal(recovered.healthStatus, 'HEALTHY');
      assert.equal(recovered.consecutiveFailures, 0);
      assert.equal(recovered.circuitOpenUntil, null);
    });
    await t.test('unchanged KEV snapshots enrich later CVEs and invalidate on source edits', async () => {
      await reset();
      const cve = vulnerability();
      const source = {
        id: 'kev',
        name: 'KEV',
        type: 'CISA_KEV',
        url: 'https://example.com/kev',
        authType: 'NONE',
        enabled: true,
        rateLimitPerMin: 60,
      };
      await save('feeds', 'kev', source);
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async (_, options) => {
        assert.equal(options?.headers?.['If-None-Match'], undefined);
        return {
          status: 200,
          headers: { etag: '"catalog-1"' },
          body: JSON.stringify({
            vulnerabilities: [
              {
                cveID: cve.cveId,
                dateAdded: '2026-01-01',
                dueDate: '2026-02-01',
                requiredAction: 'Patch',
                knownRansomwareCampaignUse: 'Unknown',
              },
            ],
          }),
        };
      });
      await save('cveData', cve.cveId, cve);
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async (_, options) => {
        assert.equal(options?.headers?.['If-None-Match'], '"catalog-1"');
        return { status: 304, headers: {}, body: '' };
      });
      assert.equal((await get<NormalizedCVE>(pool, 'cveData', cve.cveId))?.cisaKev.isKev, true);
      await save('feeds', 'kev', {
        ...(await get<any>(pool, 'feeds', 'kev')),
        url: 'https://example.com/other',
      });
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async (_, options) => {
        assert.equal(options?.headers?.['If-None-Match'], undefined);
        return { status: 200, headers: {}, body: '{"vulnerabilities":[]}' };
      });
      assert.equal((await get<NormalizedCVE>(pool, 'cveData', cve.cveId))?.cisaKev.isKev, false);
      assert.equal((await get<any>(pool, 'feeds', 'kev')).etag, undefined);
    });
    await t.test('renamed assets invalidate queued rendered systems and rebuild once', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
      await save('watchlist', 'asset', asset());
      await save('cveData', vulnerability().cveId, vulnerability());
      await save('recipients', 'rec', {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      });
      await run();
      await save('watchlist', 'asset', { ...asset(), assetTag: 'RENAMED' });
      // Correlation may refresh stored findings before old queued payload is checked.
      await run();
      let sent = 0;
      await deliverNext(pool, config, request, async () => {
        sent++;
        return 'must-not-send';
      });
      assert.equal(sent, 0);
      await run();
      await deliverNext(pool, config, request, async (job) => {
        assert.match(job.payload.text, /RENAMED/);
        sent++;
        return 'accepted';
      });
      assert.equal(sent, 1);
      await run();
      assert.equal(
        (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='QUEUED'")).rows[0].n,
        0,
      );
    });
    await t.test('interleaved dispatches count each CVE dispatch only once', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
      await save('watchlist', 'asset', asset());
      await save('cveData', vulnerability().cveId, vulnerability());
      await save('recipients', 'rec', {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      });
      await run();
      const advisory = (await list<any>(pool, 'advisories'))[0];
      const findings = await list<Finding>(pool, 'findings');
      await deliverNext(pool, config, request, async () => 'accepted-a');
      await transaction(pool, (db) => queueAdvisory(db, advisory, findings, undefined, 'dispatch-b'));
      await deliverNext(pool, config, request, async () => 'accepted-b');
      await save('recipients', 'rec-2', {
        id: 'rec-2',
        name: 'Second',
        email: 'second@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      });
      await transaction(pool, (db) => queueAdvisory(db, advisory, findings));
      await deliverNext(pool, config, request, async () => 'accepted-a-second');
      assert.equal((await get<any>(pool, 'alertedCves', vulnerability().cveId)).dispatchCount, 2);
      assert.equal((await list(pool, 'alertDispatches')).length, 2);
    });
    await t.test('feed credential rotation resets validator, health history and cooldown', async () => {
      await reset();
      const data = {
        name: 'Rotated source',
        type: 'JSON_SEARCH_API',
        url: 'https://example.com/feed',
        authType: 'API_KEY',
        authSecretKey: 'new-secret',
        rateLimitPerMin: 60,
        enabled: true,
      };
      await save('feeds', 'rotated', {
        ...data,
        id: 'rotated',
        etag: 'old-etag',
        lastSync: '2026-01-01T00:00:00Z',
        itemCountLastRun: 12,
        consecutiveFailures: 5,
        circuitOpenUntil: '2099-01-01T00:00:00Z',
      });
      await transaction(pool, (db) =>
        applyCommand(db, config, { action: 'feed.save', id: 'rotated', data, actor: 'test' }),
      );
      const saved = await get<any>(pool, 'feeds', 'rotated');
      assert.equal(saved.etag, undefined);
      assert.equal(saved.lastSync, null);
      assert.equal(saved.itemCountLastRun, 0);
      assert.equal(saved.consecutiveFailures, 0);
      assert.equal(saved.circuitOpenUntil, null);
      await transaction(pool, (db) =>
        applyCommand(db, config, {
          action: 'feed.import',
          data: [{ ...data, id: 'rotated', etag: 'invented', lastSync: '2026-01-01T00:00:00Z' }],
          actor: 'test',
        }),
      );
      const imported = await get<any>(pool, 'feeds', 'rotated');
      assert.equal(imported.etag, undefined);
      assert.equal(imported.lastSync, null);
    });
    await t.test('complete KEV and EPSS snapshots clear stale enrichment', async () => {
      await reset();
      const cve = vulnerability();
      cve.cisaKev = {
        isKev: true,
        dateAdded: '2026-01-01',
        dueDate: '2026-02-01',
        requiredAction: 'Patch now',
      };
      cve.epss = { score: 0.9, percentile: 0.99 };
      await save('cveData', cve.cveId, cve);
      await save('watchlist', 'asset', asset());
      await save('feeds', 'kev-feed', {
        id: 'kev-feed',
        name: 'KEV test',
        type: 'CISA_KEV',
        url: 'https://8.8.8.8/kev',
        authType: 'NONE',
        rateLimitPerMin: 60,
        enabled: true,
        healthStatus: 'UNTESTED',
        lastSync: null,
        latencyMs: 0,
        vendorSeed: false,
        itemCountLastRun: 0,
        ssrfValidated: false,
      });
      await save('feeds', 'epss-feed', {
        id: 'epss-feed',
        name: 'EPSS test',
        type: 'EPSS_API',
        url: 'https://8.8.8.8/epss',
        authType: 'NONE',
        rateLimitPerMin: 60,
        enabled: true,
        healthStatus: 'UNTESTED',
        lastSync: null,
        latencyMs: 0,
        vendorSeed: false,
        itemCountLastRun: 0,
        ssrfValidated: false,
      });
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async (url) => ({
        status: 200,
        body: url.endsWith('/kev') ? '{"vulnerabilities":[]}' : '{"total":0,"data":[]}',
        headers: {},
      }));
      const refreshed = await get<NormalizedCVE>(pool, 'cveData', cve.cveId);
      assert.deepEqual(refreshed?.cisaKev, { isKev: false });
      assert.deepEqual(refreshed?.epss, { score: 0, percentile: 0 });
    });
    await t.test('same-run CVEs receive targeted EPSS enrichment before dispatch', async () => {
      await reset();
      await save('watchlist', 'asset', asset());
      const baseFeed = {
        name: 'Test',
        authType: 'NONE',
        rateLimitPerMin: 60,
        enabled: true,
        consecutiveFailures: 0,
      };
      await save('feeds', 'json', {
        ...baseFeed,
        id: 'json',
        type: 'JSON_SEARCH_API',
        url: 'https://8.8.8.8/cves',
      });
      await save('feeds', 'epss', { ...baseFeed, id: 'epss', type: 'EPSS_API', url: 'https://8.8.8.8/epss' });
      const targeted: string[] = [];
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async (value) => {
        const url = new URL(value);
        if (url.pathname === '/cves')
          return { status: 200, headers: {}, body: JSON.stringify([vulnerability()]) };
        targeted.push(url.searchParams.get('cve')!);
        return {
          status: 200,
          headers: {},
          body: JSON.stringify({
            total: 1,
            data: [{ cve: vulnerability().cveId, epss: '0.8', percentile: '0.95' }],
          }),
        };
      });
      assert.deepEqual(targeted, [vulnerability().cveId]);
      assert.equal((await list<Finding>(pool, 'findings'))[0].cve.epss.score, 0.8);
    });
    await t.test(
      'responses from sources changed during ingestion cannot overwrite health or cache',
      async () => {
        await reset();
        const source = {
          id: 'changed',
          name: 'Test',
          type: 'JSON_SEARCH_API',
          url: 'https://8.8.8.8/old',
          authType: 'NONE',
          rateLimitPerMin: 60,
          enabled: true,
          healthStatus: 'UNTESTED',
        };
        await save('feeds', source.id, source);
        await queueRun(pool, 24, 'test');
        await processPipeline(pool, config, async () => {
          await save('feeds', source.id, { ...source, url: 'https://8.8.8.8/new' });
          return { status: 200, headers: {}, body: JSON.stringify([vulnerability()]) };
        });
        assert.equal((await list(pool, 'cveData')).length, 0);
        assert.equal((await get<any>(pool, 'feeds', source.id)).healthStatus, 'UNTESTED');
        assert.ok(
          (await list<any>(pool, 'executions'))[0].logs.some((line: string) =>
            line.includes('obsolete response ignored'),
          ),
        );
      },
    );
    await t.test('notification bundles obey severity and KEV subscriptions without cross-talk', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
      await save('watchlist', 'asset', asset());
      const high = vulnerability(),
        low = {
          ...vulnerability(),
          cveId: 'CVE-2026-98002',
          cvss: { ...vulnerability().cvss, severity: 'LOW', score: 2 },
        };
      high.cisaKev = { isKev: true };
      await save('cveData', high.cveId, high);
      await save('cveData', low.cveId, low);
      for (const tier of ['ALL_SEVERITIES', 'CRITICAL_HIGH_ONLY', 'CISA_KEV_ONLY'])
        await save('recipients', tier, {
          id: tier,
          name: tier,
          email: `${tier.toLowerCase()}@example.invalid`,
          enabled: true,
          subscriptionTier: tier,
        });
      await run();
      const jobs = (await pool.query('SELECT target_id,payload FROM outbox')).rows;
      assert.equal(jobs.length, 4);
      for (const job of jobs.filter((job) => job.target_id !== 'ALL_SEVERITIES'))
        assert.deepEqual(job.payload.cveIds, [high.cveId]);
      while (await deliverNext(pool, config, request, async () => 'mock-accepted')) {
        /* Drain only mock transports. */
      }
      await run();
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM outbox')).rows[0].n, 4);
    });
    await t.test(
      'security team ALL_SEVERITIES recipient receives any threat notification',
      async () => {
        await reset();
        await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
        await save('watchlist', 'asset', asset());
        // Threats across every severity level, all matching the same inventory.
        for (const [i, severity] of (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const).entries()) {
          await save('cveData', `CVE-2026-820${i + 1}`, {
            ...vulnerability(),
            cveId: `CVE-2026-820${i + 1}`,
            cvss: { ...vulnerability().cvss, severity, score: i + 2 },
          });
        }
        // Notification group Security Team, Subscription Filter Tier all severity.
        await save('recipients', 'sec-team', {
          id: 'sec-team',
          name: 'Security Team',
          email: 'sec-team@example.invalid',
          role: 'security',
          enabled: true,
          deliveryGroup: 'SECURITY_TEAM',
          subscriptionTier: 'ALL_SEVERITIES',
        });
        await run();
        const jobs = (await pool.query('SELECT target_id,payload,status FROM outbox')).rows;
        // ALL_SEVERITIES must receive every severity group — one job per severity.
        assert.equal(jobs.length, 4);
        assert.ok(jobs.every((job) => job.target_id === 'sec-team'));
        const received = jobs.flatMap((job) => job.payload.cveIds as string[]);
        for (let i = 0; i < 4; i++)
          assert.ok(received.includes(`CVE-2026-820${i + 1}`));
        // Delivery revalidation must accept all severities for ALL_SEVERITIES recipients.
        let transports = 0;
        while (await deliverNext(pool, config, request, async () => {
          transports++;
          return 'accepted';
        })) {}
        assert.equal(transports, 4);
        assert.equal(
          (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='ACCEPTED'")).rows[0].n,
          4,
        );
      },
    );
    await t.test(
      'combined digest sends at most one email per recipient without leaking other tiers',
      async () => {
        await reset();
        await save('settings', 'main', {
          ...DEFAULT_SETTINGS,
          autoDispatchEnabled: true,
          digestBatchingEnabled: true,
          digestWindowMinutes: 1,
        });
        await save('watchlist', 'asset', asset());
        const high = vulnerability(),
          low = {
            ...vulnerability(),
            cveId: 'CVE-2026-98002',
            cvss: { ...vulnerability().cvss, severity: 'LOW', score: 2 },
          };
        high.cisaKev = { isKev: true };
        await save('cveData', high.cveId, high);
        await save('cveData', low.cveId, low);
        for (const tier of ['ALL_SEVERITIES', 'CRITICAL_HIGH_ONLY', 'CISA_KEV_ONLY'])
          await save('recipients', tier, {
            id: tier,
            name: tier,
            email: `${tier.toLowerCase()}@example.invalid`,
            enabled: true,
            subscriptionTier: tier,
          });

        await run();
        // Nothing is sent immediately: the batch must survive until the window
        // elapses and be flushed by the worker, not by the pipeline transaction.
        assert.equal((await pool.query('SELECT count(*)::int AS n FROM outbox')).rows[0].n, 0);
        // A second run inside the window must extend the same batch, not create
        // a second one.
        await run();
        const buffered = await get<any>(pool, 'digestBuffer', 'pending');
        assert.equal(buffered.items.length, 2);
        // The worker flushes only after the window elapses. Move the deadline
        // into the past instead of sleeping for a real minute.
        await save('digestBuffer', 'pending', {
          ...buffered,
          flushAt: new Date(Date.now() - 1000).toISOString(),
        });

        await flushDueDigest(pool);
        const jobs = (await pool.query('SELECT target_id,payload,status FROM outbox')).rows;
        assert.equal(jobs.length, 3);
        assert.equal(jobs.filter((job) => job.status === 'QUEUED').length, 3);
        for (const job of jobs) {
          const ids = job.payload.cveIds.slice().sort();
          if (job.target_id === 'ALL_SEVERITIES')
            assert.deepEqual(ids, [high.cveId, low.cveId].sort());
          else assert.deepEqual(ids, [high.cveId]);
          assert.match(job.payload.text, /Findings:/);
        }
        const all = jobs.find((job) => job.target_id === 'ALL_SEVERITIES')!;
        assert.match(all.payload.subject, /Vulnerability digest:/);
        assert.match(all.payload.html, new RegExp(`data-pdf-cve="${high.cveId}" data-pdf-severity="HIGH"`));
        assert.match(all.payload.html, new RegExp(`data-pdf-cve="${low.cveId}" data-pdf-severity="LOW"`));
        assert.match(all.payload.text, new RegExp(high.cveId));
        assert.match(all.payload.text, new RegExp(low.cveId));

        // Re-queueing the same content under a fresh advisory ID is idempotent.
        const advisory = (await list<Advisory>(pool, 'advisories'))[0];
        const digestFindings = await list<Finding>(pool, 'findings');
        const duplicate = await transaction(pool, (db) =>
          queueDigestAdvisory(db, { ...advisory, id: 'ADV-duplicate' }, digestFindings, undefined),
        );
        assert.equal(duplicate.jobs, 0);
        assert.equal((await pool.query('SELECT count(*)::int AS n FROM outbox')).rows[0].n, 3);

        // A transient transport failure must leave the job retryable, not drop
        // it and not create a second copy.
        assert.equal(
          await deliverNext(pool, config, request, async () => {
            throw Object.assign(new Error('temporary transport outage'), { code: 'ECONNRESET', command: 'CONN' });
          }),
          true,
        );
        const retry = (
          await pool.query("SELECT status,attempts,next_attempt FROM outbox WHERE attempts=1")
        ).rows[0];
        assert.equal(retry.status, 'QUEUED');
        assert.ok(new Date(retry.next_attempt).getTime() > Date.now());
        assert.equal(
          (await list<any>(pool, 'emailLogs')).some((log) => log.status === 'RETRYING'),
          true,
        );
        await pool.query("UPDATE outbox SET next_attempt=now() WHERE status='QUEUED'");

        while (await deliverNext(pool, config, request, async () => 'mock-accepted')) {
          /* Drain the digest jobs, including the retried one. */
        }
        assert.equal(
          (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='ACCEPTED'")).rows[0].n,
          3,
        );
        assert.equal(
          (await pool.query("SELECT count(*)::int AS n FROM records WHERE kind='emailLogs'")).rows[0].n,
          3,
        );

        // A later pipeline pass must not re-queue findings already delivered.
        await run();
        assert.equal((await pool.query('SELECT count(*)::int AS n FROM outbox')).rows[0].n, 3);
        assert.equal(await flushDueDigest(pool), 0);
      },
    );
    await t.test('email retry policy persists and bounds delivery attempts', async () => {
      await reset();
      // Persist through the same validated command path the Settings page uses.
      await transaction(pool, (db) =>
        applyCommand(db, config, {
          action: 'settings.save',
          data: {
            autoDispatchEnabled: true,
            emailRetryEnabled: true,
            emailRetryMaxAttempts: 2,
            emailRetryInitialDelayMinutes: 3,
            emailRetryMaxDelayMinutes: 7,
          },
          actor: 'test',
        }),
      );
      const persisted = await get<any>(pool, 'settings', 'main');
      assert.equal(persisted.emailRetryEnabled, true);
      assert.equal(persisted.emailRetryMaxAttempts, 2);
      assert.equal(persisted.emailRetryInitialDelayMinutes, 3);
      assert.equal(persisted.emailRetryMaxDelayMinutes, 7);

      const setupDelivery = async () => {
        await save('watchlist', 'asset', asset());
        await save('cveData', vulnerability().cveId, vulnerability());
        await save('recipients', 'retry-recipient', {
          id: 'retry-recipient',
          name: 'Retry test',
          email: 'retry@example.invalid',
          enabled: true,
          subscriptionTier: 'ALL_SEVERITIES',
        });
        await run();
      };
      await setupDelivery();
      const schedule = (await list<any>(pool, 'emailLogs'))[0].retrySchedule;
      assert.deepEqual(schedule, ['3m', '6m']);

      assert.equal(
        await deliverNext(pool, config, request, async () => {
          throw new Error('temporary transport outage');
        }),
        true,
      );
      let job = (await pool.query("SELECT status,attempts,next_attempt FROM outbox WHERE attempts=1"))
        .rows[0];
      assert.equal(job.status, 'QUEUED');
      const delayMs = new Date(job.next_attempt).getTime() - Date.now();
      assert.ok(delayMs > 120_000 && delayMs <= 200_000, `unexpected retry delay ${delayMs}ms`);

      await pool.query("UPDATE outbox SET next_attempt=now() WHERE status='QUEUED'");
      assert.equal(
        await deliverNext(pool, config, request, async () => {
          throw new Error('temporary transport outage');
        }),
        true,
      );
      job = (await pool.query('SELECT status,attempts FROM outbox')).rows[0];
      assert.equal(job.status, 'FAILED');
      assert.equal(job.attempts, 2);
      const failedLog = (await list<any>(pool, 'emailLogs'))[0];
      assert.equal(failedLog.status, 'FAILED');
      assert.equal(failedLog.attemptCount, 2);

      // Disabling retry makes the first transient failure terminal.
      await reset();
      await transaction(pool, (db) =>
        applyCommand(db, config, {
          action: 'settings.save',
          data: { autoDispatchEnabled: true, emailRetryEnabled: false },
          actor: 'test',
        }),
      );
      await setupDelivery();
      await deliverNext(pool, config, request, async () => {
        throw new Error('temporary transport outage');
      });
      job = (await pool.query('SELECT status,attempts FROM outbox')).rows[0];
      assert.equal(job.status, 'FAILED');
      assert.equal(job.attempts, 1);
    });
    await t.test('queued delivery rechecks changed recipient subscriptions', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
      await save('watchlist', 'asset', asset());
      await save('cveData', vulnerability().cveId, vulnerability());
      const recipient = {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      };
      await save('recipients', recipient.id, recipient);
      await run();
      await save('recipients', recipient.id, { ...recipient, subscriptionTier: 'CISA_KEV_ONLY' });
      let transports = 0;
      await deliverNext(pool, config, request, async () => {
        transports++;
        return 'must-not-send';
      });
      assert.equal(transports, 0);
      assert.equal((await pool.query('SELECT status FROM outbox')).rows[0].status, 'FAILED');
    });
    await t.test(
      'queued payloads cannot send stale CVE severity or remediation after an update',
      async () => {
        await reset();
        await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
        await save('watchlist', 'asset', asset());
        const cve = vulnerability();
        await save('cveData', cve.cveId, cve);
        await save('recipients', 'rec', {
          id: 'rec',
          name: 'Test',
          email: 'test@example.invalid',
          enabled: true,
          subscriptionTier: 'ALL_SEVERITIES',
        });
        await run();
        await save('cveData', cve.cveId, {
          ...cve,
          remediation: { ...cve.remediation, immediateActions: ['Updated vendor action'] },
        });
        let transports = 0;
        await deliverNext(pool, config, request, async () => {
          transports++;
          return 'must-not-send';
        });
        assert.equal(transports, 0);
        assert.equal((await pool.query('SELECT status FROM outbox')).rows[0].status, 'FAILED', JSON.stringify((await pool.query('SELECT payload,error FROM outbox')).rows));
        await run();
        assert.equal(
          (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='QUEUED'")).rows[0].n,
          1,
        );
      },
    );
    await t.test(
      'queued delivery survives enrichment-only CVE updates without a rebuild',
      async () => {
        await reset();
        await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
        await save('watchlist', 'asset', asset());
        const cve = vulnerability();
        await save('cveData', cve.cveId, cve);
        await save('recipients', 'rec', {
          id: 'rec',
          name: 'Test',
          email: 'test@example.invalid',
          enabled: true,
          subscriptionTier: 'ALL_SEVERITIES',
        });
        await run();

        // Only enrichment and metadata fields that do NOT affect advisory
        // content or matching applicability are updated. EPSS score, exploit
        // status, source-feed attribution and modification timestamps all
        // refresh independently of matching, so the queued advisory should
        // remain current and deliverable without a rebuild.
        await save('cveData', cve.cveId, {
          ...cve,
          epss: { score: 0.85, percentile: 0.97 },
          exploitStatus: 'Code',
          sourceFeeds: [{ id: 'refresh', name: 'Feed', type: 'JSON_SEARCH_API', url: 'https://8.8.8.8/cves' }],
          modifiedDate: new Date().toISOString(),
        });

        let transports = 0;
        const delivered = await deliverNext(pool, config, request, async () => {
          transports++;
          return 'must-not-send';
        });
        assert.equal(transports, 1);
        assert.equal(delivered, true);
        assert.equal(
          (await pool.query('SELECT status FROM outbox')).rows[0].status,
          'ACCEPTED',
        );
      },
    );
    await t.test(
      'legacy queued payloads without revision evidence are rebuilt before transport',
      async () => {
        await reset();
        await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
        await save('watchlist', 'asset', asset());
        await save('cveData', vulnerability().cveId, vulnerability());
        await save('recipients', 'rec', {
          id: 'rec',
          name: 'Test',
          email: 'test@example.invalid',
          enabled: true,
          subscriptionTier: 'ALL_SEVERITIES',
        });
        await run();
        await pool.query("UPDATE outbox SET payload=payload-'cveRevisions'");
        let transports = 0;
        const delivered = await deliverNext(pool, config, request, async () => {
          transports++;
          return 'must-not-send';
        });
        assert.equal(delivered, true);
        // The payload is rebuilt from the current cache in place, so the job
        // delivers its current content instead of demanding an operator rebuild.
        assert.equal(transports, 1);
        const job = (await pool.query('SELECT status,payload FROM outbox')).rows[0];
        assert.equal(job.status, 'ACCEPTED');
        assert.ok(job.payload.cveRevisions[vulnerability().cveId]);
        assert.match(job.payload.text, /CVE-2026-98001 \| HIGH/);
        // No recovery rebuild is triggered once the rebuilt payload is accepted.
        assert.equal((await pool.query('SELECT count(*)::int AS n FROM outbox')).rows[0].n, 1);
      },
    );
    await t.test(
      'legacy queued payloads whose evidence cannot be rebuilt recover from current inventory',
      async () => {
        await reset();
        await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
        await save('watchlist', 'asset', asset());
        const cve = vulnerability();
        await save('cveData', cve.cveId, cve);
        await save('recipients', 'rec', {
          id: 'rec',
          name: 'Test',
          email: 'test@example.invalid',
          enabled: true,
          subscriptionTier: 'ALL_SEVERITIES',
        });
        await run();
        await pool.query("UPDATE outbox SET payload=payload-'cveRevisions'");
        // The CVE is no longer in the cache, so no revision evidence can be
        // produced for it and the queued bundle is stale by definition. The run
        // itself is driven below (a cache purge alone does not supersede it).
        await transaction(pool, (db) => db.query("DELETE FROM records WHERE kind='cveData' "));
        // Withdrawal invalidates even the trusted finding snapshot retained
        // after cache cleanup; it must never be used to rebuild a delivery.
        await save('cveWithdrawals', cve.cveId, { modifiedDate: new Date(Date.parse(cve.modifiedDate) + 1000).toISOString() });
        let transports = 0;
        await deliverNext(pool, config, request, async () => {
          transports++;
          return 'must-not-send';
        });
        assert.equal(transports, 0);
        assert.equal((await pool.query('SELECT status FROM outbox')).rows[0].status, 'FAILED', JSON.stringify((await pool.query('SELECT payload,error FROM outbox')).rows));
        assert.match((await pool.query('SELECT error FROM outbox')).rows[0].error, /no longer applicable/);
        // Recovery did not need a rebroadcast (nothing was still deliverable), so
        // no follow-up run was scheduled: the invalidation is applied by the next
        // ordinary run, which the test drives explicitly.
        await processPipeline(pool, config, request);
        const findings = await list<Finding>(pool, 'findings');
        assert.equal(findings[0].notificationStatus, 'NOT_APPLICABLE');
        assert.equal(findings[0].advisoryId, null);
        assert.equal((await pool.query("SELECT count(*)::int AS n FROM outbox WHERE status='QUEUED'")).rows[0].n, 0);
      },
    );
    await t.test('jobs without revision evidence are rebuilt in place by the recovery path', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: true });
      await save('watchlist', 'asset', asset());
      await save('cveData', vulnerability().cveId, vulnerability());
      await save('recipients', 'rec', {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      });
      await run();
      // A webhook endpoint gives the advisory a second transport job.
      await save('webhooks', 'hook', {
        id: 'hook',
        name: 'Test hook',
        url: encrypt('https://example.invalid/hook', [config.ENCRYPTION_KEY], 'webhook-url:hook'),
        secretToken: encrypt('secret', [config.ENCRYPTION_KEY], 'webhook:hook'),
        provider: 'GENERIC_HMAC',
        events: ['ALL'],
        enabled: true,
        deliveryCount: 0,
      });
      // Only findings without an advisory binding are queued, so clear it first.
      await transaction(pool, (db) =>
        db.query("UPDATE records SET data=data-'advisoryId' WHERE kind='findings'"),
      );
      await run();
      await pool.query("UPDATE outbox SET payload=payload-'cveRevisions'");
      const jobs = (await pool.query('SELECT * FROM outbox ORDER BY channel')).rows as Job[];
      assert.equal(jobs.length, 2);
      const stale = jobs[0];
      const sibling = jobs[1];
      // The sibling was already rejected by its transport; recovery must repair
      // the remaining legacy payloads rather than fail them as well.
      await pool.query("UPDATE outbox SET status='FAILED',error='transport rejected' WHERE id=$1", [sibling.id]);
      await rebuildFromCurrentInventory(pool, stale.advisory_id, 'Some advisory findings are no longer applicable');
      const recovered = (await pool.query('SELECT status,payload FROM outbox WHERE id=$1', [stale.id])).rows[0];
      assert.equal(recovered.status, 'QUEUED');
      assert.ok(recovered.payload.cveRevisions[vulnerability().cveId]);
      assert.ok(recovered.payload.findingRevisions);
      // The sibling that failed for a transport reason is left untouched.
      assert.equal(
        (await pool.query('SELECT error FROM outbox WHERE id=$1', [sibling.id])).rows[0].error,
        'transport rejected',
      );
    });
    await t.test('daily digest jobs carry revision evidence and deliver without a legacy rebuild', async () => {
      await reset();
      const cve = vulnerability();
      // A real pipeline-matched finding, so delivery revalidation reproduces
      // the same CPE verdict the digest was built from.
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: false });
      await save('watchlist', 'asset', asset());
      await save('cveData', cve.cveId, cve);
      await run();
      const [matched] = await list<Finding>(pool, 'findings');
      assert.equal(matched.notificationStatus, 'QUEUED_FOR_DISPATCH');
      const producingRun = (
        await pool.query("SELECT id FROM records WHERE kind='executions' ORDER BY updated_at DESC LIMIT 1")
      ).rows[0];
      assert.equal(matched.executionId, producingRun.id);
      await save('settings', 'main', {
        ...DEFAULT_SETTINGS,
        timezone: 'UTC',
        schedulerEnabled: false,
        dailyDigest: { enabled: true, time: '00:00', includeHealthReport: false },
      });
      await save('recipients', 'rec', {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        dailyDigest: true,
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'ALL_SEVERITIES',
      });
      assert.equal(await runDailyDigest(pool), 1);
      const job = (await pool.query('SELECT payload FROM outbox')).rows[0];
      assert.deepEqual(job.payload.cveIds, [cve.cveId]);
      assert.ok(job.payload.cveRevisions[cve.cveId]);
      assert.ok(job.payload.findingRevisions[matched.id]);
      assert.match(job.payload.subject, /Daily Vulnerability Notification/);
      assert.match(job.payload.text, /CVE-2026-98001/);
      let transports = 0;
      assert.equal(
        await deliverNext(pool, config, request, async () => {
          transports++;
          return 'mock-accepted';
        }),
        true,
      );
      const delivered = (await pool.query('SELECT status,error FROM outbox')).rows[0];
      // The digest payload carries revision evidence on its own, so delivery
      // validates it directly instead of failing with the legacy-payload error
      // and needing a rebuild.
      assert.equal(transports, 1, String(delivered.error));
      assert.equal(delivered.status, 'ACCEPTED');
      assert.equal(delivered.error, null);
    });
    await t.test('daily digest follows the Settings timezone, with a default when unset', async () => {
      await reset();
      await save('recipients', 'rec', {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        dailyDigest: true,
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'ALL_SEVERITIES',
      });
      // Pick a zone whose local date differs from UTC right now, so a schedule
      // that ignored the setting would be observably wrong.
      const zones = ['Pacific/Kiritimati', 'Pacific/Pago_Pago'];
      const keyFor = (zone: string, at = Date.now()) =>
        new Intl.DateTimeFormat('en-CA', {
          timeZone: zone,
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
        }).format(at);
      // The daily digest title renders its calendar date as ddMMMyyyy (e.g. 31Oct2026).
      const DIGEST_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const displayFor = (isoKey: string) => {
        const [y, m, d] = isoKey.split('-');
        const name = DIGEST_MONTHS[Number(m) - 1];
        return `${String(d).padStart(2, '0')}${name}${y}`;
      };
      const configured = zones.find((zone) => keyFor(zone) !== keyFor('UTC'));
      assert.ok(configured, 'no zone currently differs from UTC by a calendar day');
      const defaultTimezone = resolveTimezone();
      // Pin the expected day when the digest is queued: a run that straddles
      // local midnight between this assertion and the job would otherwise read
      // as a timezone bug.
      const digestDay = keyFor(resolveTimezone(configured));
      for (const [timezone, expected] of [
        [configured, configured],
        // Unset, blank and unusable values fall back to the documented default.
        [undefined, defaultTimezone],
        ['', defaultTimezone],
        ['Not/AZone', defaultTimezone],
      ] as const) {
        await reset();
        await save('settings', 'main', {
          ...DEFAULT_SETTINGS,
          timezone,
          dailyDigest: { enabled: true, time: '00:00', includeHealthReport: true },
        });
        await save('recipients', 'rec', {
          id: 'rec',
          name: 'Test',
          email: 'test@example.invalid',
          enabled: true,
          dailyDigest: true,
          deliveryGroup: 'SECURITY_TEAM',
          subscriptionTier: 'ALL_SEVERITIES',
        });
        assert.equal(await runDailyDigest(pool), 1, `digest not queued for ${timezone}`);
        const [job] = (await pool.query('SELECT payload,advisory_id FROM outbox')).rows;
        const expectedKey: string = expected === configured ? digestDay : keyFor(resolveTimezone(expected));
        assert.equal(
          job.advisory_id,
          `${DEFAULT_SETTINGS.advisoryPrefix}DAILY_${expectedKey.replace(/-/g, '')}`,
          `digest for ${timezone} used the wrong calendar day`,
        );
        assert.match(job.payload.subject, new RegExp(displayFor(expectedKey)));
      }
    });
    await t.test('a digest tick with no recipients does not consume the day', async () => {
      await reset();
      await save('settings', 'main', {
        ...DEFAULT_SETTINGS,
        timezone: 'UTC',
        dailyDigest: { enabled: true, time: '00:00', includeHealthReport: false },
      });
      await save('watchlist', 'asset', asset());
      await save('cveData', vulnerability().cveId, vulnerability());
      await run();
      await transaction(pool, (db) =>
        db.query("UPDATE records SET created_at=now() WHERE kind='findings'"),
      );

      // The worker polls every minute. Before anyone has opted in, the tick must
      // report nothing sent without claiming today — otherwise the findings that
      // arrive later that day are never delivered.
      assert.equal(await runDailyDigest(pool), 0);
      assert.equal(
        (await get<any>(pool, 'systemState', 'dailyDigest-schedule'))?.lastKey,
        undefined,
        'an empty tick must not claim the calendar day',
      );

      // A recipient opts in later the same day; the digest must still go out.
      await save('recipients', 'rec', {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        dailyDigest: true,
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'ALL_SEVERITIES',
      });
      assert.equal(await runDailyDigest(pool), 1);
      let transports = 0;
      assert.equal(
        await deliverNext(pool, config, request, async () => {
          transports++;
          return 'mock-accepted';
        }),
        true,
      );
      const job = (await pool.query('SELECT status,error FROM outbox')).rows[0];
      assert.equal(transports, 1, String(job.error));
      assert.equal(job.status, 'ACCEPTED');

      // The day is now claimed: a later tick must not send a second digest.
      assert.equal(await runDailyDigest(pool), 0);
    });
    await t.test('an empty daily digest is skipped, a health-only one delivers', async () => {
      const configure = async (includeHealthReport: boolean, timezone?: string) => {
        await reset();
        await save('settings', 'main', {
          ...DEFAULT_SETTINGS,
          timezone,
          dailyDigest: { enabled: true, time: '00:00', includeHealthReport },
        });
        await save('recipients', 'rec', {
          id: 'rec',
          name: 'Test',
          email: 'test@example.invalid',
          enabled: true,
          dailyDigest: true,
          deliveryGroup: 'SECURITY_TEAM',
          subscriptionTier: 'ALL_SEVERITIES',
        });
      };

      // Nothing to report and no health section: queue nothing rather than an
      // empty advisory that the delivery worker must reject as stale.
      await configure(false);
      assert.equal(await runDailyDigest(pool), 0);
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM outbox')).rows[0].n, 0);

      // With the health section enabled the digest has real content, so an
      // otherwise finding-less bundle must still deliver.
      await configure(true);
      assert.equal(await runDailyDigest(pool), 1);
      let transports = 0;
      assert.equal(
        await deliverNext(pool, config, request, async () => {
          transports++;
          return 'mock-accepted';
        }),
        true,
      );
      const job = (await pool.query('SELECT status,error FROM outbox')).rows[0];
      assert.equal(transports, 1, String(job.error));
      assert.equal(job.status, 'ACCEPTED');
    });
    await t.test('daily digest avoids the stale-bundle loop for review-held findings', async () => {
      await reset();
      // The operator set a 100% confidence bar, so real matches are held for review
      // (REVIEW_REQUIRED). Queueing is off for this run, so the held finding is
      // captured on its own rather than consumed by the stale-bundle path.
      await save('settings', 'main', {
        ...DEFAULT_SETTINGS,
        autoDispatchEnabled: false,
        autoDispatchConfidenceThreshold: 100,
      });
      // A 90% correlation is held only by the 100% bar, so the hold is purely
      // policy-driven and dropping the bar makes the same match deliverable.
      const plain = vulnerability() as Partial<NormalizedCVE>;
      delete plain.versionRange;
      const cve: NormalizedCVE = {
        ...plain,
        cvss: { ...plain.cvss!, severity: 'MEDIUM', score: 5 },
        cpeMatches: [cpe('*')],
        cpeMatchDetails: [{ criteria: cpe('*') }],
        cisaKev: { isKev: false },
      } as NormalizedCVE;
      await save('watchlist', 'asset', asset());
      await save('cveData', cve.cveId, cve);
      // Under the 100% bar the real match is held for review. It is captured before
      // the operator lowers the bar, so it is held on purpose when the digest runs.
      // Queueing is disabled for this run so the held finding is not consumed by
      // the stale-bundle path; the digest must decide on its own.
      await run();
      const [held] = await list<Finding>(pool, 'findings');
      assert.equal(held.notificationStatus, 'REVIEW_REQUIRED', held.matchingEvidence);
      assert.match(held.matchingEvidence, /confidence is below the 100% auto-dispatch threshold/);
      // The operator lowers the bar after the run. The stored state of the held
      // finding is therefore stale on purpose: re-running now would promote it,
      // and the digest below must not depend on that having happened.
      await save('settings', 'main', {
        ...DEFAULT_SETTINGS,
        timezone: 'UTC',
        schedulerEnabled: false,
        autoDispatchEnabled: true,
        autoDispatchConfidenceThreshold: 90,
        dailyDigest: { enabled: true, time: '00:00', includeHealthReport: false },
      });
      // The digest only sees findings created in the last 24 hours, and the day is
      // claimed by date key, so reset the claim to the current UTC day.
      await transaction(pool, (db) =>
        db.query("UPDATE records SET created_at=now() WHERE kind='findings'"),
      );
      await save('recipients', 'rec', {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        dailyDigest: true,
        deliveryGroup: 'SECURITY_TEAM',
        subscriptionTier: 'ALL_SEVERITIES',
      });
      await transaction(pool, (db) =>
        db.query(
          "DELETE FROM records WHERE kind='systemState' AND id='dailyDigest-schedule'",
        ),
      );
      // The digest re-evaluates the window against the current 90% policy.
      assert.equal(await runDailyDigest(pool), 1, JSON.stringify(await get(pool, 'systemState', 'dailyDigest-schedule')) + JSON.stringify(await list(pool,'recipients')));

      let transports = 0;
      assert.equal(
        await deliverNext(pool, config, request, async () => {
          transports++;
          return 'mock-accepted';
        }),
        true,
      );
      const job = (await pool.query('SELECT status,error,payload FROM outbox')).rows[0];
      assert.equal(transports, 1, String(job.error));
      assert.equal(job.status, 'ACCEPTED');
      // The digest carries every finding in the window, including one the policy
      // still considers limited-confidence: there is no review queue, and the
      // email states the limitation on the finding itself.
      assert.deepEqual(job.payload.includedFindingIds, [held.id]);
      assert.match(job.payload.text, new RegExp(held.cveId));
      const finding = (await list<Finding>(pool, 'findings')).find((f) => f.id === held.id)!;
      assert.equal(finding.notificationStatus, 'AUTO_DISPATCHED');
      assert.ok(finding.autoDispatchedAt);

      // A held finding is dispatched on a non-digest bundle too, so the digest
      // path is not the only one that delivers limited-confidence findings.
      await transaction(pool, (db) =>
        db.query(
          "UPDATE records SET data=(data-'autoDispatchedAt'-'advisoryId')||'{\"notificationStatus\":\"QUEUED_FOR_DISPATCH\"}'::jsonb WHERE kind='findings'",
        ),
      );
      await save('settings', 'main', {
        ...DEFAULT_SETTINGS,
        timezone: 'UTC',
        schedulerEnabled: false,
        autoDispatchConfidenceThreshold: 100,
        dailyDigest: { enabled: true, time: '00:00', includeHealthReport: false },
      });
      await pool.query('DELETE FROM outbox');
      // Only the stored dispatch state changes; the tightened policy still holds
      // the finding, so a non-digest bundle must refuse it.
      const [heldAgain] = await list<Finding>(pool, 'findings');
      assert.equal(heldAgain.notificationStatus, 'QUEUED_FOR_DISPATCH');
      const advisory: Advisory = {
        id: 'ADV-held',
        title: 'Held finding notice',
        severity: 'HIGH',
        cveIds: [finding.cveId],
        findingIds: [finding.id],
        createdDate: new Date().toISOString(),
        deliveryStatus: 'PENDING',
        recipientCount: 0,
        executiveSummary: 'Held',
        remediationInstructions: 'Review',
        vendorLink: '',
        affectedSystems: [finding.matchedAssetName],
        isDigestBatch: false,
      };
      await transaction(pool, (db) => queueAdvisory(db, advisory, [heldAgain]));
      let deliveredTransports = 0;
      await deliverNext(pool, config, request, async () => {
        deliveredTransports++;
        return 'held-delivered';
      });
      const delivered = (await pool.query('SELECT status,error,payload FROM outbox')).rows[0];
      assert.equal(deliveredTransports, 1, 'a limited-confidence finding must reach the transport');
      assert.equal(delivered.status, 'ACCEPTED');
      assert.equal(delivered.error, null, 'no review routing or stale-bundle failure');
      // The document states the limitation rather than the finding being withheld.
      assert.match(delivered.payload.html, /Low confidence/);
      const announcedAgain = (await list<Finding>(pool, 'findings')).find((f) => f.id === finding.id)!;
      assert.ok(announcedAgain.reviewNotifiedAt, 'the delivered finding is recorded as announced');
      // A hold the pipeline cannot change must not trigger a rebuild loop.
      assert.equal(
        (await list<any>(pool, 'executions')).filter((execution) => execution.status === 'QUEUED').length,
        0,
      );
    });
    await t.test('a limited-confidence finding is delivered alongside its confirmed siblings', async () => {
      await reset();
      // Reproduces a production daily digest: one bundle per recipient that mixes a
      // finding withheld by the confidence policy with findings that are still
      // confirmed. Automated dispatch is off, so the findings are recorded without
      // an advisory and the bundle is assembled explicitly, as an operator or a
      // digest would.
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: false });
      await save('watchlist', 'asset', asset());
      const policyHeld = {
        ...vulnerability(),
        cveId: 'CVE-2026-98010',
        applicabilityRequiresReview: false,
        cpeMatches: [cpe('*').replace(':example:', ':example_alias:')],
        cpeMatchDetails: undefined,
        versionRange: undefined,
      };
      const confirmedCve = {
        ...vulnerability(),
        cveId: 'CVE-2026-98011',
        applicabilityRequiresReview: false,
        cpeMatchDetails: undefined,
      };
      await save('aliases', 'vendor-alias', {
        id: 'vendor-alias', scope: 'VENDOR', canonical: 'example', aliases: ['example_alias'],
        source: 'MANUAL', createdAt: new Date().toISOString(),
      });
      await save('cveData', policyHeld.cveId, policyHeld);
      await save('cveData', confirmedCve.cveId, confirmedCve);
      await save('recipients', 'rec', {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      });
      await run();
      const findings = await list<Finding>(pool, 'findings');
      const held = findings.find((finding) => finding.cveId === policyHeld.cveId)!;
      const confirmed = findings.find((finding) => finding.cveId === confirmedCve.cveId)!;
      assert.ok(held && confirmed, JSON.stringify(findings.map((f) => [f.cveId, f.matchingMethod, f.matchingEvidence])));
      // The operator tightens the policy before delivery: the 85% alias correlation
      // is now held, while the 100% strict-CPE correlation stays deliverable.
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: false, autoDispatchConfidenceThreshold: 95 });
      const advisory: Advisory = {
        id: 'ADV-mixed',
        title: 'Mixed bundle',
        severity: 'HIGH',
        cveIds: [held.cveId, confirmed.cveId].sort(),
        findingIds: [held.id, confirmed.id],
        createdDate: new Date().toISOString(),
        deliveryStatus: 'PENDING',
        recipientCount: 0,
        executiveSummary: 'Mixed',
        remediationInstructions: 'Review',
        vendorLink: '',
        affectedSystems: [held.matchedAssetName],
        isDigestBatch: false,
      };
      await pool.query('DELETE FROM outbox');
      await transaction(pool, (db) => queueAdvisory(db, advisory, [held, confirmed]));
      const queuedRuns = async () =>
        (await list<any>(pool, 'executions')).filter((execution) => execution.status === 'QUEUED').length;

      let transports = 0;
      await deliverNext(pool, config, request, async () => {
        transports++;
        return 'mixed-accepted';
      });
      assert.equal(transports, 1, 'one consolidated email carries both findings');
      const delivered = (await pool.query("SELECT status,payload FROM outbox WHERE status='ACCEPTED'")).rows[0];
      assert.ok(delivered, 'the mixed bundle is delivered, not failed as stale');
      assert.deepEqual([...delivered.payload.includedFindingIds].sort(), [held.id, confirmed.id].sort());
      // The limited-confidence finding is disclosed on its own card, not dropped.
      assert.match(delivered.payload.html, /Low confidence/);
      assert.equal(await queuedRuns(), 0, 'delivering a held finding must not schedule a rebuild');
      for (const id of [held.id, confirmed.id]) {
        const saved = (await list<Finding>(pool, 'findings')).find((finding) => finding.id === id)!;
        assert.ok(saved.reviewNotifiedAt, `finding ${id} is recorded as announced`);
      }
    });
    await t.test('an operator-approved send of a limited-confidence finding is delivered', async () => {
      await reset();
      const cve = {
        ...vulnerability(),
        cveId: 'CVE-2026-98010',
        applicabilityRequiresReview: false,
        cpeMatchDetails: undefined,
      };
      // A policy above the 100% strict-CPE correlation holds the finding.
      await save('settings', 'main', { ...DEFAULT_SETTINGS, autoDispatchEnabled: false, autoDispatchConfidenceThreshold: 101 });
      await save('watchlist', 'asset', asset());
      await save('cveData', cve.cveId, cve);
      await save('recipients', 'rec', {
        id: 'rec',
        name: 'Test',
        email: 'test@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      });
      await run();
      const [queued] = await list<Finding>(pool, 'findings');
      assert.equal(queued.notificationStatus, 'REVIEW_REQUIRED', queued.matchingEvidence);
      // The confidence policy no longer withholds a finding: a held finding is
      // dispatched (with its limitation stated), and an operator approval only
      // confirms the edits on an already-queued email.
      const advisory: Advisory = {
        id: 'ADV-approved',
        title: 'Approved notice',
        severity: 'HIGH',
        cveIds: [queued.cveId],
        findingIds: [queued.id],
        createdDate: new Date().toISOString(),
        deliveryStatus: 'PENDING',
        recipientCount: 0,
        executiveSummary: 'Approved',
        remediationInstructions: 'Review',
        vendorLink: '',
        affectedSystems: [queued.matchedAssetName],
        isDigestBatch: false,
      };
      await pool.query('DELETE FROM outbox');
      await transaction(pool, (db) => queueAdvisory(db, advisory, [queued]));
      await pool.query('UPDATE outbox SET review_approved=true');
      let transports = 0;
      await deliverNext(pool, config, request, async () => {
        transports++;
        return 'approved-accepted';
      });
      assert.equal(transports, 1, 'the approved finding reaches the transport');
      const job = (await pool.query('SELECT status,error,payload FROM outbox')).rows[0];
      assert.equal(job.status, 'ACCEPTED', JSON.stringify(job));
      assert.match(job.payload.html, /Low confidence/);
      const announced = (await list<Finding>(pool, 'findings')).find((f) => f.id === queued.id)!;
      assert.ok(announced.reviewNotifiedAt);
    });
    await t.test('NVD withdrawals invalidate cached findings and block older feed resurrection', async () => {
      await reset();
      await save('watchlist', 'asset', asset());
      const original = { ...vulnerability(), modifiedDate: '2026-01-01T00:00:00Z' };
      await save('cveData', original.cveId, original);
      await run();
      const source = {
        id: 'nvd',
        name: 'NVD test',
        type: 'NVD_API',
        url: 'https://8.8.8.8/nvd',
        authType: 'NONE',
        rateLimitPerMin: 60,
        enabled: true,
      };
      await save('feeds', source.id, source);
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => ({
        status: 200,
        headers: {},
        body: JSON.stringify({
          totalResults: 1,
          startIndex: 0,
          vulnerabilities: [
            { cve: { id: original.cveId, lastModified: '2026-02-01T00:00:00Z', vulnStatus: 'Rejected' } },
          ],
        }),
      }));
      assert.equal(await get(pool, 'cveData', original.cveId), undefined);
      assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'NOT_APPLICABLE');
      await assert.rejects(
        transaction(pool, (db) =>
          applyCommand(db, config, { action: 'cve.save', data: original, actor: 'test' }),
        ),
        /withdrawn/,
      );
      await save('feeds', source.id, { ...source, type: 'JSON_SEARCH_API' });
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => ({
        status: 200,
        headers: {},
        body: JSON.stringify([original]),
      }));
      assert.equal(await get(pool, 'cveData', original.cveId), undefined);
    });
    await t.test('alias promotion freezes a learned relation and revocation tombstones it', async () => {
      await reset();
      const createdAt = new Date().toISOString();
      const auto: AliasEntry = {
        id: 'auto:vendor:acme corp',
        scope: 'VENDOR',
        canonical: 'acme corp',
        aliases: ['acme_inc'],
        source: 'AUTO',
        provenance: 'INVENTORY',
        createdAt,
        firstSeenAt: createdAt,
        lastSeenAt: createdAt,
        expiresAt: new Date(Date.parse(createdAt) + 86400000).toISOString(),
      };
      await save('aliases', auto.id, auto);
      await transaction(pool, (db) =>
        applyCommand(db, config, { action: 'alias.promote', id: auto.id, actor: 'test' }),
      );
      const promoted = await get<AliasEntry>(pool, 'aliases', auto.id);
      assert.equal(promoted?.source, 'MANUAL');
      assert.equal(promoted?.provenance, 'OPERATOR');
      assert.equal(promoted?.expiresAt, undefined);
      assert.deepEqual(promoted?.aliases, ['acme_inc']);

      const product: AliasEntry = {
        id: 'auto:product:widget pro',
        scope: 'PRODUCT',
        canonical: 'widget pro',
        aliases: ['widget_pro'],
        source: 'AUTO',
        provenance: 'INVENTORY',
        createdAt,
        firstSeenAt: createdAt,
        lastSeenAt: createdAt,
        expiresAt: new Date(Date.parse(createdAt) + 86400000).toISOString(),
      };
      await save('aliases', product.id, product);
      await transaction(pool, (db) =>
        applyCommand(db, config, { action: 'alias.revoke', id: product.id, actor: 'test' }),
      );
      assert.equal(await get(pool, 'aliases', product.id), undefined);
      const tombstone = await get<AliasEntry>(pool, 'aliases', `revoked:${product.id}`);
      assert.equal(tombstone?.source, 'REVOKED');
      assert.deepEqual(tombstone?.aliases, []);
      assert.deepEqual(tombstone?.revokedAliases, ['widget_pro']);

      // The revocation blocks re-learning while the promoted row is preserved
      // as an operator decision.
      const persisted = await list<AliasEntry>(pool, 'aliases');
      assert.deepEqual(
        deriveInventoryAliases(
          [
            {
              vendor: 'Acme Corp',
              product: 'Widget Pro',
              cpes: ['cpe:2.3:a:acme_inc:widget_pro:1.0:*:*:*:*:*:*:*'],
              active: true,
            },
          ],
          persisted,
        ),
        [],
      );
    });
    await t.test('alias changes during ingestion are reloaded inside the commit transaction', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false });
      // Asset whose CPE vendor (acme_inc) differs from the inventory vendor
      // (Acme Corp) so an AUTO alias is derivable from inventory.
      const aliasedAsset: WatchListItem = {
        id: 'aliased-asset',
        vendor: 'Acme Corp',
        product: 'Widget Pro',
        cpes: ['cpe:2.3:a:acme_inc:widget_pro:1.0:*:*:*:*:*:*:*'],
        assetTag: 'TEST',
        ownerGroup: 'test',
        active: true,
        createdAt: new Date().toISOString(),
      };
      await save('watchlist', aliasedAsset.id, aliasedAsset);
      const feedSource = { id: 'alias-nvd', name: 'NVD', type: 'NVD_API', url: 'https://example.com/nvd', authType: 'NONE', rateLimitPerMin: 600, enabled: true };
      await save('feeds', feedSource.id, feedSource);
      const cve: NormalizedCVE = {
        ...vulnerability(),
        cveId: 'CVE-2026-98002',
        cpeMatches: ['cpe:2.3:a:acme_inc:widget_pro:*:*:*:*:*:*:*:*'],
        versionRange: { versionEndExcluding: '2.0' },
      };
      await save('cveData', cve.cveId, cve);
      // Pre-existing AUTO alias derived from inventory CPE vendor mismatch.
      const createdAt = new Date().toISOString();
      const autoAlias: AliasEntry = {
        id: 'auto:vendor:acme corp',
        scope: 'VENDOR',
        canonical: 'acme corp',
        aliases: ['acme_inc'],
        source: 'AUTO',
        provenance: 'INVENTORY',
        createdAt,
        firstSeenAt: createdAt,
        lastSeenAt: createdAt,
        expiresAt: new Date(Date.parse(createdAt) + 86400000).toISOString(),
      };
      await save('aliases', autoAlias.id, autoAlias);
      // Promote the AUTO alias to MANUAL *during* ingestion. Before the fix the
      // pipeline used a stale aliasEntries snapshot committed before network I/O
      // and overwrote the promotion back to AUTO.
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => {
        await transaction(pool, (db) =>
          applyCommand(db, config, { action: 'alias.promote', id: autoAlias.id, actor: 'test' }),
        );
        return { status: 200, headers: {}, body: JSON.stringify({ startIndex: 0, totalResults: 0, vulnerabilities: [] }) };
      });
      const promoted = await get<AliasEntry>(pool, 'aliases', autoAlias.id);
      assert.equal(promoted?.source, 'MANUAL', 'promotion must survive the pipeline commit');
      assert.equal(promoted?.provenance, 'OPERATOR');
      assert.deepEqual(promoted?.aliases, ['acme_inc'], 'alias aliases must be preserved');
    });
    await t.test('alias revocation during ingestion is reloaded and blocks re-learning', async () => {
      await reset();
      await save('settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false });
      const aliasedAsset: WatchListItem = {
        id: 'revoked-asset',
        vendor: 'Acme Corp',
        product: 'Widget Pro',
        cpes: ['cpe:2.3:a:acme_inc:widget_pro:1.0:*:*:*:*:*:*:*'],
        assetTag: 'TEST',
        ownerGroup: 'test',
        active: true,
        createdAt: new Date().toISOString(),
      };
      await save('watchlist', aliasedAsset.id, aliasedAsset);
      const feedSource = { id: 'revoke-nvd', name: 'NVD', type: 'NVD_API', url: 'https://example.com/nvd', authType: 'NONE', rateLimitPerMin: 600, enabled: true };
      await save('feeds', feedSource.id, feedSource);
      const cve: NormalizedCVE = {
        ...vulnerability(),
        cveId: 'CVE-2026-98003',
        cpeMatches: ['cpe:2.3:a:acme_inc:widget_pro:*:*:*:*:*:*:*:*'],
        versionRange: { versionEndExcluding: '2.0' },
      };
      await save('cveData', cve.cveId, cve);
      const createdAt = new Date().toISOString();
      const autoAlias: AliasEntry = {
        id: 'auto:vendor:acme corp',
        scope: 'VENDOR',
        canonical: 'acme corp',
        aliases: ['acme_inc'],
        source: 'AUTO',
        provenance: 'INVENTORY',
        createdAt,
        firstSeenAt: createdAt,
        lastSeenAt: createdAt,
        expiresAt: new Date(Date.parse(createdAt) + 86400000).toISOString(),
      };
      await save('aliases', autoAlias.id, autoAlias);
      // Revoke the AUTO alias during ingestion. Before the fix, the stale snapshot
      // would re-add the alias from desiredAutoAliases, resurrecting a relation
      // the operator explicitly blocked.
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, async () => {
        await transaction(pool, (db) =>
          applyCommand(db, config, { action: 'alias.revoke', id: autoAlias.id, actor: 'test' }),
        );
        return { status: 200, headers: {}, body: JSON.stringify({ startIndex: 0, totalResults: 0, vulnerabilities: [] }) };
      });
      const tombstone = await get<AliasEntry>(pool, 'aliases', `revoked:${autoAlias.id}`);
      assert.ok(tombstone, 'revocation tombstone must be preserved');
      assert.equal(tombstone?.source, 'REVOKED');
      assert.equal((await get<AliasEntry>(pool, 'aliases', autoAlias.id))?.source, undefined, 'original AUTO row must not be resurrected');
    });
  } finally {
    await pool.end();
    await base.query(`DROP SCHEMA ${schema} CASCADE`);
    await base.end();
  }
});
