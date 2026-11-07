import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import supertest from 'supertest';
import { createPool, migrate } from '../server/db.ts';
import { createUser, deleteUser, updateUser } from '../server/auth.ts';
import { createApp } from '../server/app.ts';
import { loadConfig } from '../server/config.ts';
import { checkPassword } from '../server/secrets.ts';

const database = process.env.TEST_DATABASE_URL;
const password = 'Reset-regression-password-2026!';

test(
  'password reset binds accounts, consumes codes once, and limits public requests',
  { skip: !database },
  async (t) => {
    const base = createPool(database!);
    const schema = 'test_' + randomUUID().replaceAll('-', '');
    await base.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(database!);
    url.searchParams.set('options', `-c search_path=${schema},public`);
    const pool = createPool(url.href);
    const config = loadConfig({
      NODE_ENV: 'test',
      DATABASE_URL: url.href,
      APP_ORIGIN: 'http://localhost',
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
      WORKER_ENABLED: 'false',
    });
    try {
      await migrate(pool);
      await createUser(pool, 'alice', password, 'ADMIN', '', 'alice@example.com');
      await createUser(pool, 'bob', password, 'OPERATOR', '', 'bob@example.com');
      const app = createApp(pool, config);
      const replica = createApp(pool, config);
      const post = (route: string, body: Record<string, unknown>, target = app) =>
        supertest(target).post(`/api/password-reset/${route}`).set('Origin', config.APP_ORIGIN).send(body);
      const issue = async (username = 'alice') => {
        const result = await post('request', { username });
        assert.equal(result.status, 200, JSON.stringify(result.body));
        assert.match(result.body.code, /^\d{6}$/);
        return result.body.code as string;
      };
      const clearLimits = () => pool.query('DELETE FROM rate_limit_buckets');
      const storedHash = async (username = 'alice') =>
        (await pool.query('SELECT password_hash FROM users WHERE username=$1', [username])).rows[0]
          .password_hash;

      await t.test(
        'a code cannot reset a different username or be reused with a fabricated username',
        async () => {
          const code = await issue();
          const before = await storedHash();
          for (const username of ['bob', 'unknown']) {
            const result = await post('complete', { username, code, newPassword: password + 'new' });
            assert.equal(result.status, 400);
            assert.equal(await storedHash(), before);
          }
          assert.equal((await post('verify', { username: 'alice', code })).status, 200);
          assert.equal((await post('verify', { username: 'alice', code: 'abcdef' })).status, 400);
        },
      );
      await t.test(
        'concurrent completion has exactly one winner across replicas and revokes sessions',
        async () => {
          await clearLimits();
          const code = await issue();
          const login = await supertest(app)
            .post('/api/login')
            .set('Origin', config.APP_ORIGIN)
            .send({ username: 'alice', password });
          assert.equal(login.status, 200);
          const body = { username: 'alice', code, newPassword: password + 'new' };
          const results = await Promise.all([post('complete', body), post('complete', body, replica)]);
          assert.deepEqual(results.map((r) => r.status).sort(), [200, 400]);
          assert.equal(await checkPassword(body.newPassword, await storedHash()), true);
          assert.equal((await pool.query('SELECT 1 FROM sessions')).rowCount, 0);
          assert.equal((await post('complete', body)).status, 400);
          assert.equal((await pool.query('SELECT 1 FROM password_reset_tokens')).rowCount, 0);
        },
      );
      await t.test('issuing codes concurrently leaves one active code', async () => {
        await clearLimits();
        const responses = await Promise.all([
          post('request', { username: 'bob' }),
          post('request', { username: 'bob' }, replica),
        ]);
        assert.deepEqual(
          responses.map((r) => r.status),
          [200, 200],
        );
        assert.equal(
          (await pool.query("SELECT 1 FROM password_reset_tokens WHERE username='bob'")).rowCount,
          1,
        );
      });
      await t.test(
        'account edits preserve email-only sessions and roll back access changes if auditing fails',
        async () => {
          const bob = (await pool.query("SELECT id FROM users WHERE username='bob'")).rows[0];
          const login = await supertest(app)
            .post('/api/login')
            .set('Origin', config.APP_ORIGIN)
            .send({ username: 'bob', password });
          assert.equal(login.status, 200);
          await updateUser(pool, bob.id, { email: 'updated@example.com' }, 'alice');
          assert.equal((await pool.query('SELECT 1 FROM sessions WHERE user_id=$1', [bob.id])).rowCount, 1);
          await pool.query(`CREATE FUNCTION reject_account_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'audit unavailable'; END; $$`);
          await pool.query(`CREATE TRIGGER reject_account_audit BEFORE INSERT ON audit
        FOR EACH ROW EXECUTE FUNCTION reject_account_audit()`);
          try {
            await assert.rejects(updateUser(pool, bob.id, { role: 'VIEWER' }, 'alice'), /audit unavailable/);
            assert.equal(
              (await pool.query('SELECT role FROM users WHERE id=$1', [bob.id])).rows[0].role,
              'OPERATOR',
            );
            assert.equal((await pool.query('SELECT 1 FROM sessions WHERE user_id=$1', [bob.id])).rowCount, 1);
          } finally {
            await pool.query('DROP TRIGGER reject_account_audit ON audit');
            await pool.query('DROP FUNCTION reject_account_audit()');
          }
          await updateUser(pool, bob.id, { role: 'VIEWER' }, 'alice');
          assert.equal((await pool.query('SELECT 1 FROM sessions WHERE user_id=$1', [bob.id])).rowCount, 0);
        },
      );
      await t.test('mailbox changes, disabling, and deletion invalidate pending codes', async () => {
        const id = (await pool.query("SELECT id FROM users WHERE username='bob'")).rows[0].id;
        for (const change of [{ email: 'new@example.com' }, { disabled: true }]) {
          await clearLimits();
          const code = await issue('bob');
          await updateUser(pool, id, change, 'alice');
          assert.equal((await post('verify', { username: 'bob', code })).status, 400);
          assert.equal(
            (await pool.query("SELECT 1 FROM password_reset_tokens WHERE username='bob'")).rowCount,
            0,
          );
        }
        await updateUser(pool, id, { disabled: false }, 'alice');
        await clearLimits();
        await issue('bob');
        await deleteUser(pool, id, 'alice');
        assert.equal(
          (await pool.query("SELECT 1 FROM password_reset_tokens WHERE username='bob'")).rowCount,
          0,
        );
      });
      await t.test('administrative and authenticated password changes revoke outstanding codes', async () => {
        await clearLimits();
        const agent = supertest.agent(app);
        const login = await agent
          .post('/api/login')
          .set('Origin', config.APP_ORIGIN)
          .send({ username: 'alice', password: password + 'new' });
        assert.equal(login.status, 200);
        const csrf = login.body.csrfToken;
        const alice = (await pool.query("SELECT id FROM users WHERE username='alice'")).rows[0];
        const code = await issue();
        const changed = await agent
          .post(`/api/users/${alice.id}/reset-password`)
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', csrf)
          .send({ password });
        assert.equal(changed.status, 200);
        assert.equal((await post('verify', { username: 'alice', code })).status, 400);
        const relogin = await agent
          .post('/api/login')
          .set('Origin', config.APP_ORIGIN)
          .send({ username: 'alice', password });
        assert.equal(relogin.status, 200);
        const anotherCode = await issue();
        const selfChanged = await agent
          .post('/api/password')
          .set('Origin', config.APP_ORIGIN)
          .set('x-csrf-token', relogin.body.csrfToken)
          .send({ currentPassword: password, newPassword: password + 'new' });
        assert.equal(selfChanged.status, 200);
        assert.equal((await post('verify', { username: 'alice', code: anotherCode })).status, 400);
      });
      await t.test('expired codes cannot verify or change a password', async () => {
        await clearLimits();
        const code = await issue();
        await pool.query("UPDATE password_reset_tokens SET expires_at=now()-interval '1 second'");
        assert.equal((await post('verify', { username: 'alice', code })).status, 400);
        assert.equal(
          (await post('complete', { username: 'alice', code, newPassword: password })).status,
          400,
        );
      });
      await t.test(
        'request limits apply before lookup, share quotas across replicas and normalize paths',
        async () => {
          await clearLimits();
          for (let i = 0; i < 3; i++)
            assert.equal((await post('request', { username: 'unknown' })).status, 200);
          const limited = await post('REQUEST/', { username: 'UNKNOWN' }, replica);
          assert.equal(limited.status, 429);
          assert.ok(Number(limited.headers['retry-after']) > 0);
          assert.equal((await post('request', { username: 'different-user' })).status, 200);
        },
      );
      await t.test('verify and complete share a guessing quota across replicas', async () => {
        await clearLimits();
        for (let i = 0; i < 10; i++) {
          const result = await post(i % 2 ? 'verify' : 'complete', {
            username: 'unknown',
            code: '000000',
            newPassword: password,
          });
          assert.equal(result.status, 400);
        }
        assert.equal((await post('verify', { username: 'unknown', code: '000000' }, replica)).status, 429);
      });
      await t.test('IP limits cap requests spread across different usernames', async () => {
        await clearLimits();
        for (let i = 0; i < 15; i++)
          assert.equal((await post('request', { username: `unknown-${i}` })).status, 200);
        assert.equal((await post('request', { username: 'another-user' }, replica)).status, 429);
      });
      await t.test('development without mail refuses before minting a code for any account', async () => {
        await clearLimits();
        await pool.query('DELETE FROM password_reset_tokens');
        const development = createApp(pool, { ...config, NODE_ENV: 'development' });
        for (const username of ['alice', 'unknown'])
          assert.equal((await post('request', { username }, development)).status, 503);
        assert.equal((await pool.query('SELECT 1 FROM password_reset_tokens')).rowCount, 0);
      });
    } finally {
      await pool.end();
      await base.query(`DROP SCHEMA ${schema} CASCADE`);
      await base.end();
    }
  },
);
