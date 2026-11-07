import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cookieName, readCookie, requireRole, sessionCookieOptions } from '../server/auth.ts';
import { DEFAULT_EGRESS_HOSTS, feedEgressHosts, loadConfig } from '../server/config.ts';
import { RECOMMENDED_FEEDS } from '../server/recommendedFeeds.ts';
import type { Request, Response } from 'express';

const baseEnv = {
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://user:pass@127.0.0.1:5432/db',
  APP_ORIGIN: 'http://127.0.0.1:8080',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
};

const runRole = (roles: Parameters<typeof requireRole>, operator?: { role: string }) => {
  let error: unknown;
  let passed = false;
  const middleware = requireRole(...roles);
  middleware(
    { operator } as unknown as Request,
    {} as Response,
    ((nextError?: unknown) => {
      error = nextError;
      passed = !nextError;
    }) as never,
  );
  return { error, passed };
};

test('cookie parsing matches the exact cookie name and ignores prefix shadows', () => {
  assert.equal(readCookie('vulnstream=real-token', 'vulnstream'), 'real-token');
  assert.equal(
    readCookie('vulnstream_attacker=shadow; vulnstream=real-token', 'vulnstream'),
    'real-token',
  );
  assert.equal(readCookie('other=value; vulnstream=', 'vulnstream'), '');
  assert.equal(readCookie('vulnstream=first; vulnstream=second', 'vulnstream'), 'first');
  assert.equal(readCookie(undefined, 'vulnstream'), '');
  assert.equal(readCookie('malformed; =empty; vulnstream=ok', 'vulnstream'), 'ok');
});

test('requireRole fails closed when authentication middleware did not run', () => {
  const missing = runRole(['ADMIN']);
  assert.equal(missing.passed, false);
  assert.equal((missing.error as { status?: number }).status, 401);

  const denied = runRole(['ADMIN'], { role: 'VIEWER' });
  assert.equal(denied.passed, false);
  assert.equal((denied.error as { status?: number }).status, 403);

  const allowed = runRole(['ADMIN', 'OPERATOR'], { role: 'OPERATOR' });
  assert.equal(allowed.passed, true);
  assert.equal(allowed.error, undefined);
});

test('configuration rejects malformed database URLs and trust-all proxy settings', () => {
  assert.throws(() => loadConfig({ ...baseEnv, DATABASE_URL: 'not-a-url' }), /DATABASE_URL/);
  assert.throws(
    () => loadConfig({ ...baseEnv, DATABASE_URL: 'mysql://127.0.0.1/db' }),
    /DATABASE_URL/,
  );
  for (const trust of ['*', 'true', '0.0.0.0/0', '::/0']) {
    assert.throws(
      () => loadConfig({ ...baseEnv, TRUST_PROXY: trust }),
      /TRUST_PROXY/,
      `trust proxy ${trust} must be rejected`,
    );
  }
  assert.equal(loadConfig({ ...baseEnv, TRUST_PROXY: 'loopback,10.0.0.0/8' }).TRUST_PROXY, 'loopback,10.0.0.0/8');
  assert.equal(loadConfig(baseEnv).TRUST_PROXY, '');
});

test('production HTTP is opt-in for private IPv4 LAN origins only', () => {
  for (const APP_ORIGIN of ['http://192.168.1.72:8088', 'http://100.123.19.58:8088']) {
    const lan = loadConfig({
      ...baseEnv,
      NODE_ENV: 'production',
      APP_ORIGIN,
      ALLOW_INSECURE_HTTP: 'true',
    });
    assert.equal(cookieName(lan), 'vulnstream');
    assert.equal(sessionCookieOptions(lan).secure, false);
  }
  assert.throws(() => loadConfig({
    ...baseEnv,
    NODE_ENV: 'production',
    APP_ORIGIN: 'http://example.com',
    ALLOW_INSECURE_HTTP: 'true',
  }), /private or Tailscale IPv4 address/);
  assert.throws(() => loadConfig({
    ...baseEnv,
    NODE_ENV: 'production',
    APP_ORIGIN: 'http://192.168.1.72:8088',
  }), /HTTPS APP_ORIGIN/);
});

test('database storage modes are validated and retain filesystem defaults outside Compose', () => {
  const defaults = loadConfig(baseEnv);
  assert.equal(defaults.ML_STORAGE_MODE, 'filesystem');
  assert.equal(defaults.CORRELATION_DLQ_STORAGE_MODE, 'filesystem');
  const productionModes = loadConfig({
    ...baseEnv,
    ML_STORAGE_MODE: 'database',
    CORRELATION_DLQ_STORAGE_MODE: 'database',
  });
  assert.equal(productionModes.ML_STORAGE_MODE, 'database');
  assert.equal(productionModes.CORRELATION_DLQ_STORAGE_MODE, 'database');
  assert.throws(() => loadConfig({ ...baseEnv, ML_STORAGE_MODE: 'invalid' }), /ML_STORAGE_MODE/);
});

test('the default egress allowlist covers every redirect target of the recommended feeds', () => {
  const hosts = new Set(loadConfig(baseEnv).EGRESS_ALLOWED_HOSTS.split(','));
  // Probed over the network: each of these answers the feed URL with a
  // cross-host or same-host redirect. A hop is re-validated against the
  // allowlist, so a missing target fails the feed with "not in
  // EGRESS_ALLOWED_HOSTS".
  for (const host of [
    'api.github.com',
    'www.cisecurity.org',
    'cisecurity.org',
    'feeds.feedburner.com',
    'projectzero.google',
    'sec.cloudapps.cisco.com',
    'blog.x.com',
  ]) {
    assert.ok(hosts.has(host), `${host} must be allowlisted for its feed to follow its redirect`);
  }
  assert.ok(hosts.has('www.cisecurity.com'), 'the configured URL host must stay allowlisted');
  assert.ok(hosts.has('api.osv.dev'), 'the vulnerability search primary database must stay allowlisted');
  assert.ok(hosts.has('services.nvd.nist.gov'), 'the vulnerability search CVE enrichment must stay allowlisted');
});

test('every recommended feed URL host is allowlisted', () => {
  const hosts = new Set(loadConfig(baseEnv).EGRESS_ALLOWED_HOSTS.split(','));
  for (const feed of RECOMMENDED_FEEDS) {
    const host = new URL(feed.url).hostname.toLowerCase();
    assert.ok(hosts.has(host), `${feed.id} (${host}) must be allowlisted or its first request is blocked`);
  }
});

test('the official OTX API endpoint augments an explicit allowlist without weakening its other restrictions', () => {
  const configured = ['example.com'];
  assert.deepEqual(
    feedEgressHosts('OTX_API', 'https://otx.alienvault.com/api/v1/pulses/subscribed/', configured),
    ['example.com', 'otx.alienvault.com'],
  );
  assert.deepEqual(
    feedEgressHosts('OTX_API', 'https://otx.alienvault.com/', configured),
    configured,
  );
  assert.deepEqual(
    feedEgressHosts('RSS_ATOM', 'https://otx.alienvault.com/api/v1/pulses/subscribed/', configured),
    ['example.com', 'otx.alienvault.com'],
  );
});

test('a configured HTTPS feed adds only its exact hostname to the per-feed egress list', () => {
  const configured = ['example.com'];
  assert.deepEqual(
    feedEgressHosts('RSS_ATOM', 'https://usn.ubuntu.com/usn/usn.rss', configured),
    ['example.com', 'usn.ubuntu.com'],
  );
  assert.deepEqual(feedEgressHosts('RSS_ATOM', 'http://feeds.example.test/feed', configured), configured);
  assert.deepEqual(feedEgressHosts('WEBHOOK', 'https://feeds.example.test/feed', configured), configured);
  assert.deepEqual(feedEgressHosts('RSS_ATOM', 'https://feeds.example.test/feed', []), []);
});

test('Compose egress defaults match the application and preserve explicit empty deny-all settings', () => {
  const compose = readFileSync(new URL('../compose.yaml', import.meta.url), 'utf8');
  const hostsLine = compose.split('\n').find((line) => line.includes('EGRESS_ALLOWED_HOSTS:'));
  const extrasLine = compose.split('\n').find((line) => line.includes('EGRESS_ALLOWED_HOSTS_EXTRA:'));
  assert.ok(hostsLine);
  assert.ok(extrasLine);
  const fallback = hostsLine.match(/\$\{EGRESS_ALLOWED_HOSTS-([^}]+)\}/)?.[1];
  assert.ok(fallback, 'Compose must use the unset-only default operator');
  assert.deepEqual(
    new Set(fallback.split(',')),
    new Set(DEFAULT_EGRESS_HOSTS.split(',')),
    'Compose and application egress defaults must stay in sync',
  );
  assert.doesNotMatch(hostsLine, /\$\{EGRESS_ALLOWED_HOSTS:-/);
  assert.match(extrasLine, /\$\{EGRESS_ALLOWED_HOSTS_EXTRA-\}/);
  assert.doesNotMatch(extrasLine, /\$\{EGRESS_ALLOWED_HOSTS_EXTRA:-/);
});

test('EGRESS_ALLOWED_HOSTS_EXTRA appends to the default allowlist instead of replacing it', () => {
  const merged = loadConfig({
    ...baseEnv,
    EGRESS_ALLOWED_HOSTS_EXTRA: ' Example.test , feeds.example.test,EXAMPLE.test ',
  }).EGRESS_ALLOWED_HOSTS.split(',');
  assert.ok(merged.includes('feeds.example.test'));
  assert.deepEqual(merged.filter((host) => host === 'example.test'), ['example.test'], 'duplicates are collapsed');
  assert.ok(merged.includes('www.cisecurity.org'), 'defaults survive when only extra hosts are configured');
});

test('an explicit egress allowlist replaces defaults and extras only add declared hosts', () => {
  const merged = loadConfig({
    ...baseEnv,
    EGRESS_ALLOWED_HOSTS: ' API.SENDGRID.COM ,smtp.gmail.com',
    EGRESS_ALLOWED_HOSTS_EXTRA: 'api.sendgrid.com,example.test',
  }).EGRESS_ALLOWED_HOSTS.split(',');
  assert.deepEqual(merged, ['api.sendgrid.com', 'smtp.gmail.com', 'example.test']);
  assert.equal(loadConfig({ ...baseEnv, EGRESS_ALLOWED_HOSTS: '' }).EGRESS_ALLOWED_HOSTS, '');
});
