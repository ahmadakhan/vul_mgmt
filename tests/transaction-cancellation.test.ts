import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createPool, migrate, transaction } from '../server/db.ts';

/**
 * Cancellation must reach PostgreSQL, not just abandon a promise.
 *
 * The retention worker previously raced its sweep against a timer and simply
 * stopped waiting. The transaction kept its pool connection until the statement
 * finished — indefinitely, for a wedged one — so a hung sweep could starve the
 * pool of the connections every other job needs. `transaction` now accepts an
 * AbortSignal and cancels the backend.
 */

const database = process.env.TEST_DATABASE_URL;

test(
  'aborting a transaction cancels it and releases the connection',
  { skip: !database },
  async () => {
    const base = createPool(database!);
    const schema = 'cancel_' + randomBytes(8).toString('hex');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    // A single-connection pool: if the aborted transaction keeps its connection,
    // the follow-up claim below can never be served and this test times out.
    const pool = createPool(url.href);
    try {
      await migrate(pool);
      const controller = new AbortController();
      const running = transaction(
        pool,
        async (db) => {
          // Block until cancelled. pg_stat_activity sees wait_event 'PgSleep'.
          await db.query('SELECT pg_sleep(30)');
          return 'completed';
        },
        undefined,
        { signal: controller.signal },
      );
      setTimeout(() => controller.abort(new Error('deadline')), 250);
      const startedAt = Date.now();
      await assert.rejects(running, /cancel/i);
      // Without a real cancel the abort only clears `connectionError`, which is
      // checked after `fn` resolves: the call still waits out the full 30-second
      // sleep. Cancellation must actually reach the backend.
      assert.ok(
        Date.now() - startedAt < 5000,
        `the cancelled statement must not run to completion (waited ${Date.now() - startedAt}ms)`,
      );

      // The pool must be usable immediately: the cancelled backend was released.
      const after = await transaction(pool, async (db) => {
        const row = await db.query<{ ok: number }>('SELECT 1::int AS ok');
        return row.rows[0].ok;
      });
      assert.equal(after, 1);

      // No backend is still executing the blocked statement. `pg_stat_activity`
      // keeps the last statement of an idle connection, so the row is only
      // relevant while that backend is actually active.
      const base2 = createPool(database!);
      try {
        const active = await base2.query<{ count: number }>(
          `SELECT count(*)::int AS count FROM pg_stat_activity
            WHERE datname = current_database()
              AND pid <> pg_backend_pid()
              AND state = 'active'
              AND query LIKE '%pg_sleep(30)%'`,
        );
        assert.equal(active.rows[0].count, 0, 'the cancelled statement must not keep running');
      } finally {
        await base2.end();
      }
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
  },
);

test(
  'an already-aborted signal never starts a transaction',
  { skip: !database },
  async () => {
    const pool = createPool(database!);
    try {
      const controller = new AbortController();
      controller.abort();
      let ran = false;
      await assert.rejects(
        transaction(
          pool,
          async () => {
            ran = true;
          },
          undefined,
          { signal: controller.signal },
        ),
        /cancel/i,
      );
      assert.equal(ran, false, 'the work must not run after the deadline has passed');
      // The pool is still healthy afterwards.
      assert.equal((await pool.query('SELECT 1 AS ok')).rows[0].ok, 1);
    } finally {
      await pool.end();
    }
  },
);
