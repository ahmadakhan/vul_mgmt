import { test } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { randomBytes } from 'node:crypto';
import { createPool, migrate, put } from '../server/db.ts';
import { queryCollection } from '../server/collections.ts';

/**
 * `/api/collections/findings?executionId=…` scopes a page to one pipeline
 * execution. The SPA always sends the parameter, so a filter that is accepted
 * by the route schema but not applied by the SQL layer is invisible to the UI:
 * it renders a mixed corpus under a single-execution heading. These tests pin
 * both halves of the contract against a real database.
 */

const url = process.env.TEST_DATABASE_URL ?? '';
async function withDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T | null> {
  if (!url) return null;
  const master = createPool(url);
  const schema = `exec_filter_${randomBytes(10).toString('hex')}`;
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

const finding = (id: string, cveId: string, executionId?: string) => ({
  id,
  cveId,
  matchedAssetId: `asset-${id}`,
  matchedAssetName: `server-${id}`,
  matchingMethod: 'exact',
  notificationStatus: 'QUEUED_FOR_DISPATCH',
  status: 'MONITORED',
  ...(executionId ? { executionId } : {}),
  cve: {
    cveId,
    title: cveId,
    description: 'desc',
    publishedDate: '2026-01-01T00:00:00Z',
    modifiedDate: '2026-01-01T00:00:00Z',
    cvss: { version: '3.1', score: 7.5, vector: 'AV:N', severity: 'HIGH' },
    cwe: [],
    cpeMatches: [],
    epss: { score: 0, percentile: 0 },
    cisaKev: { inKev: false },
    exploitStatus: 'None',
    sourceFeeds: [],
  },
  timeline: [],
});

test('findings can be scoped to a single pipeline execution', { skip: !url }, async () => {
  const outcome = await withDatabase(async (pool) => {
    const runA = 'exec-a',
      runB = 'exec-b';
    await put(pool, 'findings', 'f1', finding('f1', 'CVE-2026-70001', runA));
    await put(pool, 'findings', 'f2', finding('f2', 'CVE-2026-70002', runA));
    await put(pool, 'findings', 'f3', finding('f3', 'CVE-2026-70003', runB));
    // A finding with no execution (operator import / legacy row) must never be
    // attributed to a specific run.
    await put(pool, 'findings', 'f4', finding('f4', 'CVE-2026-70004'));

    const scoped = await queryCollection(pool, 'findings', {
      limit: 50,
      offset: 0,
      filters: { executionId: runA },
    });
    assert.equal(scoped.total, 2, 'only run A findings are in scope');
    assert.deepEqual(
      scoped.items.map((item) => (item as { id: string }).id).sort(),
      ['f1', 'f2'],
    );

    const other = await queryCollection(pool, 'findings', {
      limit: 50,
      offset: 0,
      filters: { executionId: runB },
    });
    assert.equal(other.total, 1);
    assert.equal((other.items[0] as { id: string }).id, 'f3');

    const unscoped = await queryCollection(pool, 'findings', { limit: 50, offset: 0, filters: {} });
    assert.equal(unscoped.total, 4, 'omitting executionId keeps the full corpus');

    // ALL is the sentinel the client uses for "no filter"; it must not be
    // interpreted as an execution id.
    const all = await queryCollection(pool, 'findings', {
      limit: 50,
      offset: 0,
      filters: { executionId: 'ALL' },
    });
    assert.equal(all.total, 4);

    // The scoped page still composes with the other filters.
    const composed = await queryCollection(pool, 'findings', {
      limit: 50,
      offset: 0,
      filters: { executionId: runA, severity: 'CRITICAL' },
    });
    assert.equal(composed.total, 0, 'severity filter still applies inside the execution scope');
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});

test('execution scope is a bound parameter, not interpolated SQL', { skip: !url }, async () => {
  const outcome = await withDatabase(async (pool) => {
    await put(pool, 'findings', 'f1', finding('f1', 'CVE-2026-70101', 'exec-a'));
    // A value that would terminate a string literal if it were interpolated.
    const injection = "' OR 1=1 --";
    const page = await queryCollection(pool, 'findings', {
      limit: 50,
      offset: 0,
      filters: { executionId: injection },
    });
    assert.equal(page.total, 0, 'hostile executionId matches nothing and alters no predicate');
    return true;
  });
  assert.ok(outcome, 'database-backed test ran');
});
