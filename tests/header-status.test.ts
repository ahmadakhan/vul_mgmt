import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import supertest from 'supertest';
import { createApp } from '../server/app.ts';
import { loadConfig } from '../server/config.ts';
import { getSystemUptime } from '../src/utils/systemUptime.ts';

test('uptime reports the API process duration, not host uptime, and resets after restart', async (t) => {
  const pool = new pg.Pool();
  const config = loadConfig({
    NODE_ENV: 'test', DATABASE_URL: 'postgres://localhost/unused',
    APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  });
  let seconds = 90061;
  t.mock.method(process, 'uptime', () => seconds);
  const app = createApp(pool, config);
  try {
    const response = await supertest(app).get('/api/system-uptime').expect(200);
    assert.equal(response.body.systemUptime, '1d 1h 1m 1s');
    assert.equal(response.body.uptimeSeconds, seconds);
    assert.ok(Math.abs(Date.now() - Date.parse(response.body.startedAt) - seconds * 1000) < 2000);
    seconds = 5;
    const restarted = await supertest(app).get('/api/system-uptime').expect(200);
    assert.equal(restarted.body.systemUptime, '0h 0m 5s');
    assert.equal(restarted.body.uptimeSeconds, 5);
  } finally {
    await pool.end();
  }
});

test('uptime client keeps the start timestamp separate from elapsed duration and surfaces errors', async (t) => {
  let response = new Response(JSON.stringify({
    systemUptime: '0h 2m 5s', startedAt: '2026-11-04T22:00:00Z',
  }));
  t.mock.method(globalThis, 'fetch', async () => response);
  const uptime = await getSystemUptime();
  assert.deepEqual(uptime, { uptime: '0h 2m 5s' });
  response = new Response('{}', { status: 503 });
  await assert.rejects(getSystemUptime(), /HTTP 503/);
  response = new Response(JSON.stringify({ systemUptime: '' }));
  await assert.rejects(getSystemUptime(), /Invalid application uptime/);
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('Network unavailable'); });
  await assert.rejects(getSystemUptime(), /Network unavailable/);
});
