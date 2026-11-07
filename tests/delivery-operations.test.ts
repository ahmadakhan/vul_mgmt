import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import supertest from 'supertest';
import pg from 'pg';
import { z } from 'zod';
import { createApp } from '../server/app.ts';
import { createUser } from '../server/auth.ts';
import { loadConfig } from '../server/config.ts';
import { createPool, migrate } from '../server/db.ts';
import { describeError, describeFailureSummary } from '../server/events.ts';
import { enqueue } from '../server/delivery.ts';

/**
 * Operator delivery actions driven by a URL parameter, and the failure label
 * written to the operational event log.
 *
 * Both defects were found by clicking through the running application. A
 * malformed delivery id in the address bar answered every email action with
 * `500 Server operation failed` and wrote an incident-log entry, because the
 * value went straight into a uuid column parameter. Each such request also
 * created its own event message, drowning the log the message column exists to
 * make searchable.
 */

async function withDatabase<T>(fn: (pool: pg.Pool) => Promise<T>): Promise<T | null> {
  if (!process.env.TEST_DATABASE_URL) return null;
  const master = createPool(process.env.TEST_DATABASE_URL);
  const schema = `delivery_ops_${randomBytes(10).toString('hex')}`;
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

async function adminAgent(pool: pg.Pool) {
  const config = loadConfig({
    ...process.env,
    DATABASE_URL: process.env.TEST_DATABASE_URL,
    APP_ORIGIN: 'http://127.0.0.1:3998',
    ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    WORKER_ENABLED: 'false',
  });
  await createUser(pool, 'delivery-admin', 'Disposable-delivery-test-password-2026!', 'ADMIN');
  const app = createApp(pool, config, async () => ({ status: 200, headers: {}, body: '[]' }));
  const agent = supertest.agent(app);
  const login = await agent
    .post('/api/login')
    .set('Origin', config.APP_ORIGIN)
    .send({ username: 'delivery-admin', password: 'Disposable-delivery-test-password-2026!' });
  assert.equal(login.status, 200);
  return { agent, csrf: login.body.csrfToken as string, origin: config.APP_ORIGIN };
}

test(
  'a malformed delivery id is a client error on every delivery action, never a 500',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const { agent, csrf, origin } = await adminAgent(pool);
      const send = (method: 'post' | 'delete', path: string) =>
        agent[method](path).set('Origin', origin).set('x-csrf-token', csrf).send({});
      const cases = [
        ['post', '/api/email/not-a-uuid/approve'],
        ['post', '/api/email/not-a-uuid/reject'],
        ['post', '/api/email/not-a-uuid/retry'],
        ['delete', '/api/email/not-a-uuid'],
      ] as const;
      for (const [method, path] of cases) {
        const response = await send(method, path);
        assert.ok(response.status < 500, `${method.toUpperCase()} ${path} returned ${response.status}`);
        assert.equal(response.status, 400, `${method.toUpperCase()} ${path} → ${response.status}`);
        assert.match(String(response.body.error), /Invalid identifier/);
      }
      // A well-formed but unknown id keeps its existing "nothing to act on"
      // contract, so the guard did not swallow the normal path.
      assert.equal((await send('post', `/api/email/${randomUUID()}/approve`)).status, 409);
      assert.equal((await send('delete', `/api/email/${randomUUID()}`)).status, 409);
      // None of the rejected requests may look like an incident.
      const incidents = await pool.query(
        "SELECT count(*)::int AS count FROM operational_events WHERE code='http.request_failed'",
      );
      assert.equal(incidents.rows[0].count, 0, 'a client error must not be recorded as a server failure');
    });
    assert.notEqual(outcome, null);
  },
);

test(
  'bulk queue clear cancels queued, failed, and review emails but leaves sending jobs alone',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const { agent, csrf, origin } = await adminAgent(pool);
      const createJob = async (dedupe: string, initialStatus: 'QUEUED' | 'REVIEW' = 'QUEUED') => {
        const id = await enqueue(pool, 'email', 'test', 'TEST', {
          subject: dedupe,
          text: 'fixture',
          cveIds: [],
          recipientEmail: 'queue-test@example.invalid',
        }, dedupe, initialStatus);
        assert.ok(id);
        return id;
      };
      const queued = await createJob('bulk-clear-queued');
      const failed = await createJob('bulk-clear-failed');
      const review = await createJob('bulk-clear-review', 'REVIEW');
      const sending = await createJob('bulk-clear-sending');
      await pool.query("UPDATE outbox SET status='FAILED' WHERE id=$1", [failed]);
      await pool.query("UPDATE outbox SET status='SENDING' WHERE id=$1", [sending]);

      const response = await agent
        .delete('/api/email-queue')
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({});
      assert.equal(response.status, 200);
      assert.deepEqual(response.body, { success: true, removed: 3, inFlight: 1 });
      const remaining = await pool.query<{ id: string; status: string }>(
        "SELECT id,status FROM outbox WHERE channel='email' ORDER BY id",
      );
      assert.deepEqual(remaining.rows, [{ id: sending, status: 'SENDING' }]);
      for (const id of [queued, failed, review]) {
        const log = (await pool.query<{ data: { status: string; errorMessage: string } }>(
          "SELECT data FROM records WHERE kind='emailLogs' AND id=$1",
          [id],
        )).rows[0].data;
        assert.equal(log.status, 'CANCELLED');
        assert.match(log.errorMessage, /removed from the delivery queue/i);
      }
    });
    assert.notEqual(outcome, null);
  },
);

test(
  'an operator id that is not a uuid is a 400, and a valid one still updates the operator',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const { agent, csrf, origin } = await adminAgent(pool);
      const malformed = await agent
        .patch('/api/users/not-a-uuid')
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({ role: 'VIEWER', disabled: false });
      assert.equal(malformed.status, 400);

      const created = await agent
        .post('/api/users')
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({
          username: 'viewer-one',
          password: 'Disposable-viewer-password-2026!',
          role: 'VIEWER',
          email: 'viewer-one@example.com',
        });
      assert.equal(created.status, 201);
      const viewer = (await pool.query("SELECT id FROM users WHERE username='viewer-one'")).rows[0];
      const creation = (await pool.query("SELECT data FROM audit WHERE data->'context'->>'action'='operator.create' AND data->'context'->>'resourceId'=$1", [viewer.id])).rows[0].data;
      assert.equal(creation.actor, 'delivery-admin');
      assert.equal(creation.context.outcome, 'SUCCESS');
      const updated = await agent
        .patch(`/api/users/${viewer.id}`)
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({ role: 'OPERATOR', disabled: false });
       assert.equal(updated.status, 200);
     });
     assert.notEqual(outcome, null);
   },
);

test(
  'workspace accounts carry a required reset email that an administrator can edit',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const { agent, csrf, origin } = await adminAgent(pool);
      const send = (method: 'post' | 'patch', path: string, body: any) =>
        agent[method](path).set('Origin', origin).set('x-csrf-token', csrf).send(body);

      // Creating an account without an address is refused: a reset code would
      // have nowhere to go except the shared deployment mailbox.
      const missing = await send('post', '/api/users', {
        username: 'no-email',
        password: 'Disposable-viewer-password-2026!',
        role: 'VIEWER',
      });
      assert.equal(missing.status, 400);
      const malformed = await send('post', '/api/users', {
        username: 'bad-email',
        password: 'Disposable-viewer-password-2026!',
        role: 'VIEWER',
        email: 'not-an-address',
      });
      assert.equal(malformed.status, 400);

      // The address is normalized (trimmed, lowercased) on the way in.
      const created = await send('post', '/api/users', {
        username: 'email-user',
        password: 'Disposable-viewer-password-2026!',
        role: 'VIEWER',
        email: '  Email-User@Example.COM ',
      });
      assert.equal(created.status, 201);
      const row = (await pool.query("SELECT id,email FROM users WHERE username='email-user'")).rows[0];
      assert.equal(row.email, 'email-user@example.com');

      // An email-only edit is accepted and does not disturb the role.
      const edited = await send('patch', `/api/users/${row.id}`, { email: 'new-address@example.org' });
      assert.equal(edited.status, 200);
      const after = (await pool.query('SELECT email,role FROM users WHERE id=$1', [row.id])).rows[0];
      assert.equal(after.email, 'new-address@example.org');
      assert.equal(after.role, 'VIEWER');

      // An edit that changes nothing is a client error, not a silent no-op.
      assert.equal((await send('patch', `/api/users/${row.id}`, {})).status, 400);
      assert.equal((await send('patch', `/api/users/${row.id}`, { email: 'bad' })).status, 400);

      // The session payload carries the caller's own address (null until set),
      // so the account form can prefill it instead of silently clearing it.
      const session = await agent.get('/api/session');
      assert.equal(session.body.email, null, 'the administrator has no address of their own yet');

      // An address edit must not revoke the target's sessions. A role change
      // still does, so an email edit cannot quietly become an authority change.
      await pool.query(
        "INSERT INTO sessions(token_hash,user_id,csrf,expires_at,absolute_expires_at) VALUES('probe',$1,'probe',now()+interval '1 hour',now()+interval '1 day')",
        [row.id],
      );
      const sessionCount = async () =>
        (await pool.query('SELECT count(*)::int AS n FROM sessions WHERE user_id=$1', [row.id])).rows[0].n as number;
      assert.equal(await sessionCount(), 1);
      assert.equal((await send('patch', `/api/users/${row.id}`, { email: 'third@example.org' })).status, 200);
      assert.equal(await sessionCount(), 1, 'an email-only edit keeps the account signed in');
      assert.equal((await send('patch', `/api/users/${row.id}`, { role: 'OPERATOR' })).status, 200);
      assert.equal(await sessionCount(), 0, 'a role change revokes sessions');
    });
    assert.notEqual(outcome, null);
  },
);

test(
  'an operator id that is not a uuid is a 400, and a valid one is deleted from the workspace',
  { skip: !process.env.TEST_DATABASE_URL },
  async () => {
    const outcome = await withDatabase(async (pool) => {
      const { agent, csrf, origin } = await adminAgent(pool);
      const malformed = await agent
        .delete('/api/users/not-a-uuid')
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({});
      assert.equal(malformed.status, 400);

      const created = await agent
        .post('/api/users')
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({
          username: 'viewer-two',
          password: 'Disposable-viewer-password-2026!',
          role: 'VIEWER',
          email: 'viewer-two@example.com',
        });
      assert.equal(created.status, 201);
      const viewer = (await pool.query("SELECT id FROM users WHERE username='viewer-two'")).rows[0];
      const deleted = await agent
        .delete(`/api/users/${viewer.id}`)
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({});
      assert.equal(deleted.status, 200);
      const remaining = await pool.query("SELECT id FROM users WHERE username='viewer-two'");
      assert.equal(remaining.rowCount, 0);

      // An administrator cannot delete their own account.
      const adminRow = (await pool.query("SELECT id FROM users WHERE username='delivery-admin'")).rows[0];
      const selfDelete = await agent
        .delete(`/api/users/${adminRow.id}`)
        .set('Origin', origin)
        .set('x-csrf-token', csrf)
        .send({});
      assert.equal(selfDelete.status, 400);
      // The actor account must still exist.
      const stillThere = await pool.query("SELECT id FROM users WHERE username='delivery-admin'");
      assert.equal(stillThere.rowCount, 1);
    });
    assert.notEqual(outcome, null);
  },
);

test('the event-log failure label is a stable summary, not the error text', () => {
  const databaseError = Object.assign(new Error('invalid input syntax for type uuid: "not-a-uuid"'), {
    code: '22P02',
    name: 'error',
  });
  assert.equal(describeFailureSummary(databaseError), 'error');
  // The label must not vary with the caller-supplied value in the message.
  const other = Object.assign(new Error('invalid input syntax for type uuid: "x"'), { code: '22P02', name: 'error' });
  assert.equal(describeFailureSummary(databaseError), describeFailureSummary(other));

  const validation = z.uuid().safeParse('nope');
  assert.equal(validation.success, false);
  assert.equal(describeFailureSummary(validation.error), 'Validation failed');
  assert.equal(describeFailureSummary('a string'), 'Request failed');
  assert.equal(describeFailureSummary(new RangeError('boom')), 'RangeError');
  // The full message still reaches the event context, where it is not indexed
  // and not rendered as the row title.
  assert.match(String(describeError(databaseError).error), /not-a-uuid/);
});
