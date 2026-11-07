import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import supertest from 'supertest';
import { createPool, migrate, put } from '../server/db.ts';
import { createApp } from '../server/app.ts';
import { createUser } from '../server/auth.ts';
import { loadConfig } from '../server/config.ts';
import { encrypt, tokenHash } from '../server/secrets.ts';
import { DEFAULT_EMAIL_CONFIG, DEFAULT_SETTINGS } from '../shared/state.ts';

test('password reset uses the configured API provider and honors the master email switch', { skip: !process.env.TEST_DATABASE_URL }, async () => {
  const control = createPool(process.env.TEST_DATABASE_URL!);
  const schema = `reset_delivery_${randomBytes(8).toString('hex')}`;
  await control.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(process.env.TEST_DATABASE_URL!);
  url.searchParams.set('options', `-c search_path=${schema}`);
  const pool = createPool(url.href);
  try {
    await migrate(pool);
    const key = randomBytes(32).toString('base64');
    const config = loadConfig({ NODE_ENV: 'development', DATABASE_URL: url.href,
      APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: key, SMTP_HOST: '', SMTP_FROM: '' });
    await put(pool, 'settings', 'main', DEFAULT_SETTINGS);
    await createUser(pool, 'reset-operator', 'Disposable-reset-password-2026!', 'VIEWER', '', 'operator@example.invalid');
    await put(pool, 'emailConfig', 'main', { ...DEFAULT_EMAIL_CONFIG, provider: 'SENDGRID',
      fromEmail: 'security@example.invalid', apiKey: encrypt('test-provider-token', [key], 'email-provider:SENDGRID') });
    const messages: { content: { type: string; value: string }[]; attachments?: unknown[] }[] = [];
    const app = createApp(pool, config, async (endpoint, options) => {
      assert.equal(endpoint, 'https://api.sendgrid.com/v3/mail/send');
      messages.push(JSON.parse(options!.body!));
      return { status: 202, headers: { 'x-message-id': 'reset-receipt' }, body: '' };
    });
    const send = (username: string) => supertest(app).post('/api/password-reset/request')
      .set('Origin', config.APP_ORIGIN).send({ username });
    const response = await send('reset-operator');
    assert.equal(response.status, 200);
    assert.equal(response.body.code, undefined);
    assert.equal(messages.length, 1);
    assert.equal(messages[0].attachments, undefined);
    const text = messages[0].content.find((part) => part.type === 'text/plain')!.value;
    const code = /\b\d{6}\b/.exec(text)![0];
    const token = (await pool.query('SELECT code_hash FROM password_reset_tokens WHERE username=$1', ['reset-operator'])).rows[0];
    assert.equal(token.code_hash, tokenHash(code));
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM outbox')).rows[0].count, 0);
    assert.equal((await send('unknown-operator')).status, 200);
    assert.equal(messages.length, 1);
    await put(pool, 'settings', 'main', { ...DEFAULT_SETTINGS, emailEnabled: false });
    const disabled = await send('reset-operator');
    const unknown = await send('unknown-operator');
    assert.equal(disabled.status, 503);
    assert.equal(unknown.status, 503);
    assert.equal(disabled.body.error, unknown.body.error);
    assert.equal(messages.length, 1);
  } finally {
    await pool.end();
    await control.query(`DROP SCHEMA ${schema} CASCADE`);
    await control.end();
  }
});