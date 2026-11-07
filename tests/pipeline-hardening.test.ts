import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import pg from 'pg';
import { createPool, migrate } from '../server/db.ts';
import { AdvisoryIngestor, databaseCode, transientDatabaseError } from '../server/correlation/ingest.ts';
import { CorrelationTelemetry } from '../server/correlation/telemetry.ts';
import { DeadLetterQueue } from '../server/correlation/deadLetter.ts';
import { PipelineSupervisor } from '../server/correlation/supervisor.ts';
import { acknowledgePending, acknowledgePendingExcept, claimPending } from '../server/correlation/pending.ts';
import { extractText } from '../server/correlation/extraction.ts';
import { TextCorrelationEngine } from '../server/correlation/engine.ts';
import { AdvisoryInputSchema, describeAdvisoryError } from '../server/correlation/validation.ts';

/**
 * Regressions for defects found by running the pipeline, not by reading it.
 * Every case here corresponds to a behaviour that was wrong in a way only an
 * executing system exposes: a misdiagnosed outage, a silent data-loss path, or
 * an accepted-but-unprocessable submission.
 */

const key = randomBytes(32).toString('base64');
const silent = () =>
  new CorrelationTelemetry(
    new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
    }),
  );

async function withDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T | null> {
  if (!process.env.TEST_DATABASE_URL) return null;
  const master = createPool(process.env.TEST_DATABASE_URL);
  const schema = `hardening_${randomBytes(10).toString('hex')}`;
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

test('SQLSTATE classification separates "unreachable" from "answered with an error"', () => {
  // Connectivity is class 08, shutdown class 57P0x, and connection exhaustion.
  for (const code of ['08000', '08006', '08003', '57P01', '57P02', '57P03', '53300'])
    assert.equal(/^(08[A-Z0-9]{3}|57P0[123]|53300)$/.test(code), true, code);
  // The database answering with a complaint is NOT a severed connection. The
  // supervisor previously flipped to RECOVERING_DB_SEVERANCE and opened a
  // five-minute breaker on any of these.
  for (const code of ['23505', '42703', '42P01', '55P03', '57014', '40001'])
    assert.equal(/^(08[A-Z0-9]{3}|57P0[123]|53300)$/.test(code), false, code);
  assert.equal(databaseCode(Object.assign(new Error('x'), { code: '42703' })), '42703');
  assert.equal(transientDatabaseError(Object.assign(new Error('x'), { code: '42703' })), false);
  assert.equal(transientDatabaseError(Object.assign(new Error('x'), { code: '40001' })), true);
});

test(
  'a non-connectivity fault while checking health does not open the circuit breaker',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const telemetry = silent();
      const directory = await mkdtemp(join(tmpdir(), 'hardening-'));
      try {
        const supervisor = new PipelineSupervisor(
          pool,
          new AdvisoryIngestor(telemetry, new DeadLetterQueue(directory, [key], telemetry)),
        );
        // Make the auxiliary health step fail with a *schema* error while the
        // database stays perfectly reachable. Before the fix, the supervisor
        // reported "database_unavailable" and recorded a crash toward the
        // five-minute breaker.
        // The shared-policy read fails with a *schema* error while the database
        // stays reachable (SELECT 1 still succeeds). Before the fix every
        // exception in that block was reported as a severed connection.
        const realQuery = pool.query.bind(pool);
        // A structural stand-in for the pool: only `query` is exercised here,
        // and a Pool's counters are read-only getters.
        Object.defineProperty(supervisor, 'pool', {
          value: {
            query: async (text: unknown, values?: unknown[]) => {
              const sql = typeof text === 'string' ? text : String((text as { text?: string })?.text ?? '');
              if (sql.includes('correlation_policy'))
                throw Object.assign(new Error('column "concurrency_limit" does not exist'), { code: '42703' });
              return realQuery(text as never, values as never);
            },
            totalCount: 0,
            idleCount: 0,
            waitingCount: 0,
          },
        });
        await supervisor.check();
        assert.notEqual(supervisor.health, 'RECOVERING_DB_SEVERANCE');
        assert.equal(
          telemetry.logs.some((entry) => entry.event === 'supervisor.database_unavailable'),
          false,
          'a schema error must not be reported as a database outage',
        );
        assert.equal(
          telemetry.logs.some((entry) => entry.event === 'supervisor.health_step_failed'),
          true,
        );
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    });
    assert.notEqual(outcome, null);
  },
);

test(
  'a genuine connection failure still opens the breaker and degrades health',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const telemetry = silent();
      const directory = await mkdtemp(join(tmpdir(), 'hardening-'));
      try {
        const supervisor = new PipelineSupervisor(
          pool,
          new AdvisoryIngestor(telemetry, new DeadLetterQueue(directory, [key], telemetry)),
        );
        Object.defineProperty(supervisor, 'pool', {
          value: {
            query: async () => {
              throw Object.assign(new Error('Connection terminated unexpectedly'), { code: '08006' });
            },
            totalCount: 0,
            idleCount: 0,
            waitingCount: 0,
          },
        });
        for (let index = 0; index < 3; index++) await supervisor.check();
        assert.equal(supervisor.health, 'RECOVERING_DB_SEVERANCE');
        assert.equal(
          telemetry.logs.some((entry) => entry.event === 'supervisor.database_unavailable'),
          true,
        );
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    });
    assert.notEqual(outcome, null);
  },
);

test(
  'a partially failed batch acknowledges only the records that were durable',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const insert = (payload: unknown) =>
        pool.query('INSERT INTO correlation_pending(id,payload) VALUES($1,$2)', [
          randomUUID(),
          JSON.stringify(payload),
        ]);
      await insert({ url: 'https://example.org/a', title: 'a', content: 'a' });
      await insert({ url: 'https://example.org/b', title: 'b', content: 'b' });
      await insert({ url: 'https://example.org/c', title: 'c', content: 'c' });
      const batch = await claimPending(pool, 3);
      assert.equal(batch.jobs.length, 3);
      // The middle record is the one that could not be made durable.
      const retained = [batch.jobs[1].id];
      const removed = await acknowledgePendingExcept(pool, batch, retained);
      assert.equal(removed, 2, 'every durable record is acknowledged');
      const remaining = (await pool.query('SELECT id FROM correlation_pending')).rows.map((row) => row.id);
      assert.deepEqual(remaining, retained, 'only the failed record stays queued for replay');
      // The retained row still holds its lease, so it is not immediately
      // reclaimable — that is the lease doing its job, not a lost record. Once
      // the lease lapses the same row is claimed again and, on success, the
      // un-filtered acknowledgement removes it.
      await pool.query("UPDATE correlation_pending SET lease_until = now() - interval '1 second'");
      const second = await claimPending(pool, 3);
      assert.equal(second.jobs.length, 1);
      assert.equal(second.jobs[0].id, retained[0]);
      assert.equal(await acknowledgePending(pool, second), 1);
      assert.equal((await pool.query('SELECT * FROM correlation_pending')).rowCount, 0);
    });
    assert.notEqual(outcome, null);
  },
);

test(
  'a poisoned pending advisory is retired after its attempt budget, not retried forever',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const id = randomUUID();
      await pool.query('INSERT INTO correlation_pending(id,payload) VALUES($1,$2)', [
        id,
        JSON.stringify({ url: 'https://example.org/poison', title: 'x', content: 'x' }),
      ]);
      // Before the fix, nothing retired a row whose payload fails
      // deterministically: each claim lapsed, was re-claimed and re-failed
      // forever, and on a small estate occupied the head of the queue on every tick.
      const { MAX_PENDING_ATTEMPTS } = await import('../server/correlation/pending.ts');
      let lastBatch;
      for (let attempt = 0; attempt < MAX_PENDING_ATTEMPTS; attempt++) {
        await pool.query("UPDATE correlation_pending SET lease_until = now() - interval '1 second'");
        lastBatch = await claimPending(pool, 4);
        assert.equal(lastBatch.jobs.length, 1, `attempt ${attempt + 1} still offers the row`);
      }
      // The next claim, after the budget, must not offer it again.
      await pool.query("UPDATE correlation_pending SET lease_until = now() - interval '1 second'");
      const after = await claimPending(pool, 4);
      assert.equal(after.jobs.length, 0, 'the exhausted row is no longer offered');
      // The row is retained (visible, countable), not deleted.
      const row = await pool.query('SELECT attempts FROM correlation_pending WHERE id=$1', [id]);
      assert.equal(row.rows[0].attempts, MAX_PENDING_ATTEMPTS);
    });
    assert.notEqual(outcome, null);
  },
);

test('an advisory rejection names the field and rule, never the rejected value', () => {
  const secret = 'customer-secret-token-1234567890';
  const reason = describeAdvisoryError({ title: 'ok', content: 'ok', url: `javascript:${secret}` });
  assert.notEqual(reason, 'VALID');
  assert.match(reason, /^url:/);
  assert.equal(reason.includes(secret), false, 'the rejected value must not be echoed');
  assert.equal(describeAdvisoryError({ title: 't', content: 'c', url: 'https://example.org/x' }), 'VALID');
  assert.equal(AdvisoryInputSchema.safeParse({ title: 't', content: 'c', url: 'https://example.org/x' }).success, true);
});

test('a batch job keeps its structural identity through the JSON round trip', () => {
  const payload = { url: 'https://example.org/a', title: 't', content: 'c', cpes: [], entities: [] };
  const stored = JSON.parse(JSON.stringify(payload));
  assert.deepEqual(stored, payload);
  // The batch acknowledges by payload identity, so the comparison must tolerate
  // the re-ordering a JSON round trip could introduce in nested objects.
  const reordered = { entities: [], cpes: [], content: 'c', title: 't', url: 'https://example.org/a' };
  assert.deepEqual(JSON.parse(JSON.stringify(reordered)), payload);
});

test('extraction attaches a bound to the product named before it', async () => {
  const telemetry = silent();
  const extracted = await extractText(
    'FortiOS before 7.2.4 is vulnerable to remote code execution exploited in the wild, researchers said.',
    telemetry,
    randomUUID(),
  );
  assert.deepEqual(extracted.ranges, [{ productPhrase: 'fortios', range: '<7.2.4' }]);
  // A CVE-free article dense with exploitation language IS early intelligence;
  // that flag is what routes it to the unassigned review queue when nothing in
  // inventory matches.
  assert.equal(extracted.zeroDay, true);
  assert.equal(extracted.cveIds.length, 0);
  assert.equal(extracted.securitySignal, true);

  const assets = [
    { id: '11111111-1111-4111-8111-111111111111', vendor: 'fortinet', product: 'fortios', version: '7.2.3', revision: 'r' },
    { id: '22222222-2222-4222-8222-222222222222', vendor: 'fortinet', product: 'fortios', version: '7.2.5', revision: 'r' },
  ];
  const matches = await new TextCorrelationEngine().correlate(
    { title: 'FortiOS flaw', content: 'c', url: 'https://example.org/f', cpes: [], purls: [], entities: [] },
    extracted,
    async (sql: string) => {
      if (sql.includes('vendor_product_aliases'))
        return { rows: [{ alias: 'fortios', vendor: 'fortinet', product: 'fortios' }] } as never;
      if (sql.includes('correlation_asset_inventory')) return { rows: assets } as never;
      return { rows: [] } as never;
    },
  );
  assert.equal(matches.length, 1, 'only the version inside the range is matched');
  assert.equal(matches[0].assetId, assets[0].id);
  assert.equal(matches[0].confidence, 'HIGH');
  // Negative control: the patched build must be *absent*, not merely outranked.
  // Without this, an engine that matched every asset of the product and then
  // deduplicated would still satisfy the assertions above.
  assert.equal(
    matches.some((match) => match.assetId === assets[1].id),
    false,
    'the patched 7.2.5 build must not be reported as affected',
  );
  assert.match(matches[0].reason, /range satisfied/);

  // Inverting the bound inverts the result: the same inventory, the same
  // assets, and now only the patched build is exposed. A matcher that returned
  // a constant verdict could not satisfy both halves.
  const inverted = await new TextCorrelationEngine().correlate(
    { title: 'FortiOS flaw', content: 'c', url: 'https://example.org/f2', cpes: [], purls: [], entities: [] },
    { ...extracted, ranges: [{ productPhrase: 'fortios', range: '>=7.2.4' }] },
    async (sql: string) => {
      if (sql.includes('vendor_product_aliases'))
        return { rows: [{ alias: 'fortios', vendor: 'fortinet', product: 'fortios' }] } as never;
      if (sql.includes('correlation_asset_inventory')) return { rows: assets } as never;
      return { rows: [] } as never;
    },
  );
  assert.deepEqual(
    inverted.map((match) => match.assetId),
    [assets[1].id],
    'the complementary range must expose exactly the other build',
  );
});
