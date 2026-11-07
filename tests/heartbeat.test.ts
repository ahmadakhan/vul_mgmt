import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Heartbeat } from '../server/correlation/heartbeat.ts';

const healthy = () => ({ healthy: true, reason: 'HEALTHY' });
const sick = () => ({ healthy: false, reason: 'RECOVERING_DB_SEVERANCE' });

test('heartbeat is inert when no URL is configured', async () => {
  const heartbeat = new Heartbeat({ url: '', intervalMs: 1000, suppressOnUnhealthy: true });
  assert.equal(heartbeat.enabled, false);
  assert.equal(heartbeat.state.status, 'disabled');
  // Must not attempt a ping: an unconfigured receiver is the default deployment.
  let called = false;
  heartbeat['options'].fetchImpl = (async () => {
    called = true;
    return new Response('', { status: 200 });
  }) as unknown as typeof fetch;
  await heartbeat.ping(healthy);
  assert.equal(called, false);
});

test('heartbeat pings an external receiver when healthy', async () => {
  const calls: string[] = [];
  const heartbeat = new Heartbeat({
    url: 'https://receiver.invalid/ping/secret-token',
    intervalMs: 1000,
    suppressOnUnhealthy: true,
    fetchImpl: (async (input: string | URL | Request) => {
      calls.push(String(input));
      return new Response('ok', { status: 200 });
    }) as typeof fetch,
  });
  await heartbeat.ping(healthy);
  assert.equal(calls.length, 1);
  assert.equal(heartbeat.state.status, 'pinged');
  assert.ok(heartbeat.lastPingAt > 0);
  assert.equal(heartbeat.consecutiveFailures, 0);
});

test('heartbeat ALARMS BY SILENCE when the pipeline is unhealthy', async () => {
  // This is the whole point of a dead-man's switch: pinging "alive" during a
  // total ingestion outage would make the receiver believe all is well. The
  // correct behaviour is to send nothing and let the receiver's grace period
  // expire.
  let pings = 0;
  const heartbeat = new Heartbeat({
    url: 'https://receiver.invalid/ping',
    intervalMs: 1000,
    suppressOnUnhealthy: true,
    fetchImpl: (async () => {
      pings++;
      return new Response('ok', { status: 200 });
    }) as typeof fetch,
  });
  await heartbeat.ping(sick);
  assert.equal(pings, 0, 'must not ping while the pipeline cannot admit');
  assert.equal(heartbeat.state.status, 'suppressed');
  assert.equal(heartbeat.lastPingAt, 0, 'a suppressed ping is never a successful ping');
});

test('heartbeat records delivery failures without throwing', async () => {
  // A heartbeat that can crash the process it monitors is worse than none.
  const heartbeat = new Heartbeat({
    url: 'https://receiver.invalid/ping',
    intervalMs: 1000,
    suppressOnUnhealthy: true,
    fetchImpl: (async () => {
      throw new Error('network down');
    }) as unknown as typeof fetch,
  });
  await assert.doesNotReject(heartbeat.ping(healthy));
  assert.equal(heartbeat.state.status, 'failed');
  assert.equal(heartbeat.consecutiveFailures, 1);
  assert.equal(heartbeat.lastPingAt, 0);
});

test('heartbeat treats a non-2xx response as a failure', async () => {
  const heartbeat = new Heartbeat({
    url: 'https://receiver.invalid/ping',
    intervalMs: 1000,
    suppressOnUnhealthy: true,
    fetchImpl: (async () => new Response('nope', { status: 500 })) as typeof fetch,
  });
  await heartbeat.ping(healthy);
  assert.equal(heartbeat.state.status, 'failed');
  assert.equal(heartbeat.consecutiveFailures, 1);
});
