import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import type pg from 'pg';
import { createPool, migrate, put, list, get, transaction } from '../server/db.ts';
import { queueRun, processPipeline, stopRun, stopRunWithClient } from '../server/pipeline.ts';
import { loadConfig } from '../server/config.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { Finding, PipelineExecution, NormalizedCVE, WatchListItem } from '../src/types/index.ts';

const database = process.env.TEST_DATABASE_URL;
test(
  'pipeline policy and stop requests survive concurrent worker activity',
  { skip: !database },
  async (t) => {
    const base = createPool(database!);
    const schema = 'pipeline_audit_' + randomBytes(8).toString('hex');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    const pool = createPool(url.href);
    const config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url.href,
      APP_ORIGIN: 'http://localhost',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    });
    const cpe = 'cpe:2.3:a:example:widget:1.5:*:*:*:*:*:*:*';
    const asset: WatchListItem = {
      id: 'asset',
      vendor: 'example',
      product: 'widget',
      cpes: [cpe],
      assetTag: 'TEST',
      ownerGroup: 'test',
      active: true,
      createdAt: new Date().toISOString(),
    };
    const cve: NormalizedCVE = {
      cveId: 'CVE-2026-98001',
      title: 'Pipeline audit fixture',
      description: 'Test only',
      publishedDate: new Date().toISOString(),
      modifiedDate: new Date().toISOString(),
      cvss: { version: '3.1', score: 8, severity: 'HIGH', vector: '' },
      cwe: [],
      cpeMatches: [cpe],
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
    };
    const save = (kind: string, id: string, value: unknown) =>
      transaction(pool, (db) => put(db, kind, id, value));
    const reset = async (threshold = 90) => {
      await pool.query('DELETE FROM records; DELETE FROM outbox');
      await save('settings', 'main', {
        ...DEFAULT_SETTINGS,
        autoDispatchEnabled: true,
        autoDispatchConfidenceThreshold: threshold,
      });
      await save('watchlist', 'asset', asset);
      await save('cveData', cve.cveId, cve);
      await save('recipients', 'ops', {
        id: 'ops',
        name: 'Ops',
        email: 'ops@example.invalid',
        enabled: true,
        subscriptionTier: 'ALL_SEVERITIES',
      });
    };
    const noNetwork = async () => {
      throw new Error('No network expected');
    };
    const run = async () => {
      await queueRun(pool, 24, 'test');
      await processPipeline(pool, config, noNetwork);
    };
    try {
      await migrate(pool);
      await t.test('preliminary match reuse respects the configured confidence threshold', async () => {
        await reset(99);
        await run();
        assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'REVIEW_REQUIRED');
        assert.equal((await pool.query('SELECT 1 FROM outbox')).rowCount, 0);
        await save('settings', 'main', {
          ...DEFAULT_SETTINGS,
          autoDispatchEnabled: true,
          autoDispatchConfidenceThreshold: 90,
        });
        await run();
        assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'QUEUED_FOR_DISPATCH');
        assert.equal((await pool.query('SELECT 1 FROM outbox')).rowCount, 1);
      });
      await t.test('a policy edit during EPSS enrichment forces eligibility to be recomputed', async () => {
        await reset();
        await save('feeds', 'epss', {
          id: 'epss',
          name: 'EPSS',
          type: 'EPSS_API',
          url: 'https://example.com/epss',
          authType: 'NONE',
          enabled: true,
          rateLimitPerMin: 600,
        });
        await queueRun(pool, 24, 'test');
        let calls = 0;
        await processPipeline(pool, config, async () => {
          calls++;
          await save('settings', 'main', {
            ...DEFAULT_SETTINGS,
            autoDispatchEnabled: true,
            autoDispatchConfidenceThreshold: 99,
          });
          return {
            status: 200,
            headers: {},
            body: JSON.stringify({ total: 1, data: [{ cve: cve.cveId, epss: '0.8', percentile: '0.95' }] }),
          };
        });
        assert.equal(calls, 1);
        assert.equal((await list<Finding>(pool, 'findings'))[0].notificationStatus, 'REVIEW_REQUIRED');
        assert.equal((await pool.query('SELECT 1 FROM outbox')).rowCount, 0);
      });
      await t.test('a stop between checkpoint and progress write cannot be overwritten', async () => {
        await reset();
        const queued = await queueRun(pool, 24, 'test');
        const connect = pool.connect.bind(pool);
        let intercepted = false;
        // The first checkout is the worker's run-lock connection, held for the
        // whole run. An operator stop must write through that same session: a
        // fresh connection cannot take `pipeline-queue` (the worker owns it)
        // and, if it tried inside its transaction, would deadlock against it.
        let runLockClient: pg.PoolClient | undefined;
        const workerPool = new Proxy(pool, {
          get(target, property) {
            if (property !== 'connect') {
              const value = Reflect.get(target, property, target);
              return typeof value === 'function' ? value.bind(target) : value;
            }
            return async () => {
              const client = await connect();
              runLockClient ??= client;
              const query = client.query;
              const release = client.release;
              client.query = ((...args: unknown[]) => {
                const [sql, values] = args;
                const forward = () => (query as (...args: unknown[]) => unknown).apply(client, args);
                if (
                  !intercepted &&
                  typeof sql === 'string' &&
                  /^(?:INSERT INTO records|UPDATE records)/.test(sql) &&
                  Array.isArray(values) &&
                  values.some((v) => typeof v === 'string' && v.includes('"status":"RUNNING"'))
                ) {
                  intercepted = true;
                  return stopRunWithClient(pool, queued.id, 'concurrent-operator', runLockClient).then(
                    forward,
                  );
                }
                return forward();
              }) as typeof client.query;
              client.release = (error) => {
                client.query = query;
                client.release = release;
                release.call(client, error);
              };
              return client;
            };
          },
        });
        await processPipeline(workerPool, config, noNetwork);
        assert.equal(intercepted, true);
        const stopped = await get<PipelineExecution>(pool, 'executions', queued.id);
        assert.equal(stopped?.status, 'CANCELLED');
        assert.ok(stopped?.stopRequestedAt);
        assert.ok(stopped?.logs.includes('Operator requested stop'));
        assert.equal((await list(pool, 'findings')).length, 0);
        assert.equal((await pool.query('SELECT 1 FROM outbox')).rowCount, 0);
      });
      await t.test('recovery honours a durable stop without restarting the execution', async () => {
        await reset();
        const queued = await queueRun(pool, 24, 'test');
        await save('executions', queued.id, {
          ...queued,
          status: 'RUNNING',
          stopRequestedAt: new Date().toISOString(),
          logs: ['Operator requested stop'],
        });
        assert.equal(await processPipeline(pool, config, noNetwork), false);
        const stopped = await get<PipelineExecution>(pool, 'executions', queued.id);
        assert.equal(stopped?.status, 'CANCELLED');
        assert.ok(stopped?.logs.includes('Operator requested stop'));
        assert.equal((await list(pool, 'findings')).length, 0);
      });
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
  },
);
