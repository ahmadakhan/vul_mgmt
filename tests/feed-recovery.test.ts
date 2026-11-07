import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPermanentFeed, recoveryAt, recoveryDue, shouldStartAutomaticRun, isPermanentFeedFailure } from '../server/feedRecovery';
import { feedSchema } from '../server/validation.ts';
import { FeedDeferred } from '../server/ingestion.ts';
import { ingestFeed } from '../server/ingestion';
import type { ThreatFeed } from '../src/types/index.ts';
import { loadConfig } from '../server/config.ts';
const feed = { id: 'source', name: 'Source', type: 'JSON_SEARCH_API', url: 'https://example.com/feed', authType: 'NONE', rateLimitPerMin: 60, enabled: true, healthStatus: 'DOWN', recoveryDelayMinutes: 2 } as ThreatFeed;
test('failed sources recover at their persisted deadline and back off to one hour', () => {
  const now = Date.now();
  const deadline = recoveryAt(feed, 1, now);
  assert.equal(Date.parse(deadline), now + 120000);
  assert.equal(recoveryDue({ ...feed, circuitOpenUntil: deadline }, now), false);
  assert.equal(recoveryDue({ ...feed, circuitOpenUntil: deadline }, now + 120000), true);
  assert.equal(recoveryDue({ ...feed, enabled: false, circuitOpenUntil: deadline }, now + 120000), false);
  assert.equal(recoveryDue({ ...feed, healthStatus: 'HEALTHY', circuitOpenUntil: deadline }, now + 120000), false);
  assert.equal(Date.parse(recoveryAt(feed, 100, now)), now + 3600000);
  assert.equal(Date.parse(recoveryAt({ ...feed, recoveryDelayMinutes: 30 }, 1, now, 5 * 60000)), now + 1800000);
  assert.equal(Date.parse(recoveryAt(feed, 1, now, 2 * 3600000)), now + 3600000);
});
test('authentication and rate-limit HTTP failures remain recoverable', () => {
  for (const errorLog of ['HTTP 401 Unauthorized', 'HTTP 403 Forbidden', 'HTTP 408 Timeout', 'HTTP 429 Too Many Requests']) {
    assert.equal(isPermanentFeed({ ...feed, errorLog } as ThreatFeed), false);
  }
  assert.equal(isPermanentFeed({ ...feed, errorLog: 'HTTP 404 Not Found' } as ThreatFeed), true);
  assert.equal(isPermanentFeed({ ...feed, errorLog: 'Configuration error (not retryable): invalid URL' } as ThreatFeed), true);
});

test('upstream 4xx failures from ingestion errors are permanent, 401/403/408/429 are recoverable', () => {
  for (const msg of ['Feed returned HTTP 406', 'Feed returned HTTP 404 Not Found', 'Feed returned HTTP 400 Bad Request']) {
    assert.equal(isPermanentFeedFailure(new Error(msg)), true, `${msg} must be permanent`);
  }
  for (const msg of ['Feed returned HTTP 401 Unauthorized', 'Feed returned HTTP 403 Forbidden', 'Feed returned HTTP 408 Timeout', 'Feed returned HTTP 429 Too Many Requests']) {
    assert.equal(isPermanentFeedFailure(new Error(msg)), false, `${msg} must be recoverable`);
  }
  assert.equal(isPermanentFeedFailure(new Error('Outbound request timed out')), false, 'timeout must be recoverable');
  assert.equal(isPermanentFeedFailure(new Error('socket hang up')), false, 'socket hang up must be recoverable');
  assert.equal(isPermanentFeedFailure(new Error('Destination hostname is not in EGRESS_ALLOWED_HOSTS')), true, 'SSRF rejection must be permanent');
});

test('provider-requested delay (FeedDeferred) is transient, not a permanent failure', () => {
  assert.equal(isPermanentFeedFailure(new FeedDeferred(3393)), false, 'FeedDeferred must not be permanent');
  assert.equal(new FeedDeferred(3393).name, 'FeedDeferred');
  assert.match(new FeedDeferred(3393).message, /3393/);
});

test('a DOWN feed with no circuit deadline is immediately due for recovery', () => {
  const now = Date.now();
  assert.equal(recoveryDue({ ...feed, circuitOpenUntil: null }, now), true);
  assert.equal(recoveryDue({ ...feed, circuitOpenUntil: undefined }, now), true);
});

test('recovery probes run with routine scheduling disabled, while periodic runs remain disabled', () => {
  const now = Date.parse('2026-10-22T00:00:00Z');
  assert.equal(
    shouldStartAutomaticRun({
      schedulerEnabled: false,
      recoveryProbeDue: true,
      lastRun: new Date(now).toISOString(),
      intervalMinutes: 60,
    }, now),
    true,
  );
  assert.equal(
    shouldStartAutomaticRun({
      schedulerEnabled: false,
      recoveryProbeDue: false,
      lastRun: null,
      intervalMinutes: 60,
    }, now),
    false,
  );
});
test('enabled scheduler enforces its interval even when recovery work is due', () => {
  const now = Date.parse('2026-10-22T00:00:00Z');
  assert.equal(
    shouldStartAutomaticRun({
      schedulerEnabled: true,
      recoveryProbeDue: true,
      lastRun: new Date(now - 5 * 60_000).toISOString(),
      intervalMinutes: 120,
    }, now),
    false,
  );
  assert.equal(
    shouldStartAutomaticRun({
      schedulerEnabled: true,
      recoveryProbeDue: false,
      lastRun: new Date(now - 120 * 60_000).toISOString(),
      intervalMinutes: 120,
    }, now),
    true,
  );
});
test('feed settings validate bounds and retain legacy timeout behavior', () => {
  assert.equal(feedSchema.parse(feed).requestTimeoutSeconds, undefined);
  assert.equal(feedSchema.safeParse({ ...feed, requestTimeoutSeconds: 0 }).success, false);
  assert.equal(feedSchema.safeParse({ ...feed, recoveryDelayMinutes: 61 }).success, false);
});
test('custom timeout is used and a previously timed out source can ingest again', async () => {
  const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: 'postgres://unused', APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: randomBytes(32).toString('base64') });
  let fail = true;
  const request = async (_url: string, options: any) => {
    assert.equal(options.timeoutMs, 45000);
    assert.equal(options.socketTimeoutMs, 45000);
    if (fail) throw new Error('Outbound request timed out');
    return { status: 200, body: '[]', headers: {} };
  };
  const source = { ...feed, requestTimeoutSeconds: 45 };
  await assert.rejects(ingestFeed(source, 24, request, config), /timed out/);
  fail = false;
  assert.equal((await ingestFeed(source, 24, request, config)).count, 0);
});
