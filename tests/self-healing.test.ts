import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { migrate, put, list, get } from '../server/db.ts';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import { runSelfHealCheck } from '../server/selfHealing.ts';
import type { EmailRecipient, PipelineExecution, ThreatFeed } from '../src/types/index.ts';

/**
 * Regression coverage for the self-healing watchdog.
 *
 * The module queried `executions`/`feeds`/`settings` as tables — they are
 * `records` rows — so every tick threw before reaching any recovery or alert
 * path. It also sent straight to the transport under one per-component dedupe
 * key, so only the first security-team recipient received the mail and a failed
 * send was swallowed. And it re-enabled operator-disabled feeds and cleared open
 * circuits every tick.
 */
async function withDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<void> {
  if (!process.env.TEST_DATABASE_URL) return;
  const master = new pg.Client({ connectionString: process.env.TEST_DATABASE_URL });
  await master.connect();
  const schema = `selfheal_${randomBytes(8).toString('hex')}`;
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
    await fn(pool);
  } finally {
    await pool?.end().catch(() => undefined);
    await master.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(() => undefined);
    await master.end().catch(() => undefined);
  }
}

const recipient = (id: string, email: string, group?: string): EmailRecipient =>
  ({
    id,
    name: email,
    email,
    enabled: true,
    deliveryGroup: group,
    subscriptionTier: 'ALL_SEVERITIES',
    role: 'VIEWER',
    deliverySuccessRate: 0,
  }) as EmailRecipient;

const failedExecution = (id: string, endAgoMs: number): PipelineExecution =>
  ({
    id,
    status: 'FAILED',
    startTime: new Date(Date.now() - endAgoMs - 60_000).toISOString(),
    endTime: new Date(Date.now() - endAgoMs).toISOString(),
    scopeHours: 24,
    incrementalFeeds: true,
    stats: {
      recoveryAttempts: 0,
    } as PipelineExecution['stats'],
    phases: [],
    logs: ['Worker failed'],
  }) as unknown as PipelineExecution;

const feed = (id: string, overrides: Partial<ThreatFeed> = {}): ThreatFeed =>
  ({
    id,
    name: id,
    type: 'RSS_ATOM',
    url: 'https://example.com/feed',
    authType: 'NONE',
    rateLimitPerMin: 5,
    enabled: true,
    healthStatus: 'DOWN',
    lastSync: null,
    latencyMs: 0,
    itemCountLastRun: 0,
    ssrfValidated: true,
    consecutiveFailures: 2,
    circuitOpenUntil: null,
    errorLog: 'Configuration error (not retryable): bad url',
    ...overrides,
  }) as ThreatFeed;

test('concurrent self-healing ticks queue one job per recipient and one recovery', { skip: !process.env.TEST_DATABASE_URL }, async () =>
  withDatabase(async (pool) => {
    await put(pool, 'recipients', 'r1', recipient('r1', 'sec1@example.com', 'SECURITY_TEAM'));
    await put(pool, 'recipients', 'r2', recipient('r2', 'sec2@example.com', 'SECURITY_TEAM'));
    await put(pool, 'executions', 'incident', failedExecution('incident', 60000));
    await Promise.all(Array.from({ length: 4 }, () => runSelfHealCheck(pool)));
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM outbox')).rows[0].count, 2);
    assert.equal((await list<PipelineExecution>(pool, 'executions')).filter((run) => run.status === 'QUEUED').length, 1);
    assert.ok((await get<Record<string, { lastRecoveryAt?: string }>>(pool, 'systemState', 'selfHealing'))?.PIPELINE.lastRecoveryAt);
  }));

test('self-healing queue failures roll back alert claims and retry after recovery is queued', { skip: !process.env.TEST_DATABASE_URL }, async () =>
  withDatabase(async (pool) => {
    await put(pool, 'recipients', 'r1', recipient('r1', 'sec@example.com', 'SECURITY_TEAM'));
    await put(pool, 'executions', 'incident', failedExecution('incident', 60000));
    await pool.query(`CREATE FUNCTION reject_alert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected queue failure'; END $$;
      CREATE TRIGGER reject_alert BEFORE INSERT ON outbox FOR EACH STATEMENT EXECUTE FUNCTION reject_alert()`);
    await assert.rejects(runSelfHealCheck(pool), /injected queue failure/);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM outbox')).rows[0].count, 0);
    assert.equal((await get<Record<string, { lastAlertAt?: string }>>(pool, 'systemState', 'selfHealing'))?.PIPELINE.lastAlertAt, undefined);
    await pool.query('DROP TRIGGER reject_alert ON outbox');
    await runSelfHealCheck(pool);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM outbox')).rows[0].count, 1);
    assert.equal((await list<PipelineExecution>(pool, 'executions')).filter((run) => run.status === 'QUEUED').length, 1);
  }));

test('disabled email suppression is bounded and re-enabling does not lose the alert', { skip: !process.env.TEST_DATABASE_URL }, async () =>
  withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, emailEnabled: false });
    await put(pool, 'recipients', 'r1', recipient('r1', 'sec@example.com', 'SECURITY_TEAM'));
    await put(pool, 'executions', 'incident', failedExecution('incident', 60000));
    await runSelfHealCheck(pool);
    await runSelfHealCheck(pool);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM outbox')).rows[0].count, 0);
    assert.equal((await pool.query("SELECT count(*)::int AS count FROM operational_events WHERE code='selfHealing.alert_suppressed'")).rows[0].count, 1);
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, emailEnabled: true });
    await runSelfHealCheck(pool);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM outbox')).rows[0].count, 1);
  }));

test('a stale heartbeat cannot restart an explicitly disabled scheduler', { skip: !process.env.TEST_DATABASE_URL }, async () =>
  withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false });
    await put(pool, 'recipients', 'r1', recipient('r1', 'sec@example.com', 'SECURITY_TEAM'));
    await pool.query("UPDATE scheduler_state SET heartbeat=now()-interval '10 minutes' WHERE id=1");
    await runSelfHealCheck(pool);
    assert.equal((await list<PipelineExecution>(pool, 'executions')).length, 0);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM outbox')).rows[0].count, 0);
  }));

test('historical failed runs do not trigger recovery or alerts', { skip: !process.env.TEST_DATABASE_URL }, async () =>
  withDatabase(async (pool) => {
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, schedulerEnabled: false });
    await put(pool, 'recipients', 'r1', recipient('r1', 'sec@example.com', 'SECURITY_TEAM'));
    for (let index = 0; index < 20; index++) await put(pool, 'executions', `old-${index}`, failedExecution(`old-${index}`, 86400000));
    await runSelfHealCheck(pool);
    assert.equal((await list<PipelineExecution>(pool, 'executions')).filter((run) => run.status === 'QUEUED').length, 0);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM outbox')).rows[0].count, 0);
  }));

test(
  'self-healing alerts every security-team recipient once through the durable outbox',
  { skip: !process.env.TEST_DATABASE_URL },
  async () =>
    withDatabase(async (pool) => {
      await put(pool, 'recipients', 'r1', recipient('r1', 'sec1@example.com', 'SECURITY_TEAM'));
      await put(pool, 'recipients', 'r2', recipient('r2', 'sec2@example.com'));
      await put(pool, 'recipients', 'v1', recipient('v1', 'viewer@example.com', 'VIEWER'));
      await put(pool, 'executions', 'exec-failed', failedExecution('exec-failed', 5 * 60_000));

      await runSelfHealCheck(pool);

      const outbox = (
        await pool.query(
          "SELECT dedupe_key,target_id,advisory_id,payload FROM outbox WHERE channel='email' ORDER BY target_id",
        )
      ).rows;
      assert.deepEqual(
        outbox.map((row) => row.target_id),
        ['r1', 'r2'],
        'each security-team recipient gets the alert; VIEWER does not',
      );
      for (const row of outbox) {
        assert.match(row.advisory_id, /^SELFHEAL:/);
        assert.ok(row.dedupe_key.endsWith(`email:${row.target_id}`), 'dedupe key is per recipient');
        assert.match(row.payload.subject, /^\[SECURITY ALERT\]/);
      }

      // A recovery run is queued exactly once and the cooldown suppresses repeats.
      await runSelfHealCheck(pool);
      const total = (await pool.query('SELECT count(*)::int AS n FROM outbox')).rows[0].n;
      assert.equal(total, 2, 'repeated ticks inside the cooldown do not duplicate alerts');
      const queuedRuns = (await list<PipelineExecution>(pool, 'executions')).filter(
        (execution) => execution.status === 'QUEUED',
      );
      assert.equal(queuedRuns.length, 1, 'one recovery run is queued, not one per tick');
    }),
);

test(
  'self-healing re-arms only feeds it is allowed to recover',
  { skip: !process.env.TEST_DATABASE_URL },
  async () =>
    withDatabase(async (pool) => {
      await put(pool, 'recipients', 'r1', recipient('r1', 'sec1@example.com', 'SECURITY_TEAM'));
      await put(pool, 'feeds', 'broken', feed('broken'));
      await put(pool, 'feeds', 'disabled', feed('disabled', { enabled: false }));
      await put(
        pool,
        'feeds',
        'open-circuit',
        feed('open-circuit', { circuitOpenUntil: new Date(Date.now() + 600_000).toISOString() }),
      );

      await runSelfHealCheck(pool);

      const feeds = new Map((await list<ThreatFeed>(pool, 'feeds')).map((row) => [row.id, row]));
      assert.equal(
        feeds.get('broken')!.consecutiveFailures,
        2,
        'the failure counter is preserved so the breaker still escalates if the probe fails again',
      );
      assert.equal(feeds.get('broken')!.circuitOpenUntil, null, 'the stale deadline is cleared for the probe');
      assert.equal(feeds.get('broken')!.ssrfValidated, false, 'forces re-validation on the next run');
      assert.equal(feeds.get('disabled')!.enabled, false, 'operator-disabled feeds stay disabled');
      assert.equal(feeds.get('disabled')!.ssrfValidated, true, 'disabled feeds are not rewritten');
      assert.ok(
        feeds.get('open-circuit')!.circuitOpenUntil,
        'an open circuit keeps its own retry schedule instead of being cleared every tick',
      );
      assert.equal(feeds.get('open-circuit')!.ssrfValidated, true, 'an open circuit is not re-armed early');
      const alert = (await pool.query("SELECT count(*)::int AS n FROM outbox WHERE channel='email'")).rows[0].n;
      assert.equal(alert, 1, 'the security team is told a feed needed recovery');
    }),
);

test(
  'a fresh failure produces a new alert even inside the previous cooldown',
  { skip: !process.env.TEST_DATABASE_URL },
  async () =>
    withDatabase(async (pool) => {
      await put(pool, 'recipients', 'r1', recipient('r1', 'sec1@example.com', 'SECURITY_TEAM'));
      await put(pool, 'executions', 'first', failedExecution('first', 5 * 60_000));
      await runSelfHealCheck(pool);
      // Recover: the queued run now exists, so the first incident is resolved.
      await pool.query("UPDATE records SET data = data || '{\"status\":\"CANCELLED\"}'::jsonb WHERE kind='executions' AND id='first'");
      await put(pool, 'executions', 'second', failedExecution('second', 0));
      await runSelfHealCheck(pool);
      const keys = (await pool.query('SELECT dedupe_key FROM outbox')).rows.map((row) => row.dedupe_key);
      assert.equal(keys.filter((key) => key.includes(':first:')).length, 1);
      assert.equal(keys.filter((key) => key.includes(':second:')).length, 1, 'a new incident is not swallowed by the cooldown');
    }),
);
