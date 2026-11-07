import { randomBytes } from 'node:crypto';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadConfig } from '../server/config.ts';
import { ingestFeed } from '../server/ingestion.ts';
import { OTX_SUBSCRIBED_PULSES_URL, parseOtxPulsePage, validateOtxNextUrl } from '../server/otx.ts';
import { encrypt, encryptionKeys } from '../server/secrets.ts';
import { feedSchema } from '../server/validation.ts';
import type { ThreatFeed } from '../src/types/index.ts';

const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'http://localhost',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
});
const source: ThreatFeed = {
  id: 'feed-alienvault-otx',
  name: 'AlienVault OTX',
  type: 'OTX_API',
  url: OTX_SUBSCRIBED_PULSES_URL,
  authType: 'API_KEY',
  authSecretKey: encrypt('otx-test-key', encryptionKeys(config), 'feed:feed-alienvault-otx'),
  rateLimitPerMin: 60,
  enabled: true,
  healthStatus: 'UNTESTED',
  lastSync: null,
  latencyMs: 0,
  itemCountLastRun: 0,
  ssrfValidated: false,
  vendorSeed: false,
};
const sleep = async () => {};
const pulse = (id: string, name: string) => ({
  id,
  name,
  description: 'Indicators associated with CVE-2026-12345.',
  created: '2026-11-04T10:00:00Z',
  modified: new Date().toISOString(),
  tags: ['ransomware', 'threat intel'],
});

test('OTX feed requires its subscribed-pulses endpoint and an API key', () => {
  assert.equal(feedSchema.safeParse({
    name: 'OTX',
    type: 'OTX_API',
    url: OTX_SUBSCRIBED_PULSES_URL,
    authType: 'API_KEY',
    authSecretKey: 'key',
    rateLimitPerMin: 60,
    enabled: false,
  }).success, true);
  assert.equal(feedSchema.safeParse({
    name: 'OTX',
    type: 'OTX_API',
    url: 'https://otx.alienvault.com/',
    authType: 'NONE',
    rateLimitPerMin: 60,
    enabled: false,
  }).success, false);
});

test('OTX ingestion sends the API key header and converts subscribed Pulses to articles', async () => {
  const result = await ingestFeed(source, 48, async (rawUrl, options) => {
    const url = new URL(rawUrl);
    assert.equal(url.origin + url.pathname, OTX_SUBSCRIBED_PULSES_URL);
    assert.equal(url.searchParams.get('limit'), '100');
    assert.equal(options?.headers?.['X-OTX-API-KEY'], 'otx-test-key');
    assert.equal(options?.headers?.apiKey, undefined);
    return {
      status: 200,
      body: JSON.stringify({ results: [pulse('abc123', 'CVE-2026-12345 threat pulse')], next: null }),
      headers: {},
    };
  }, config, sleep);

  assert.equal(result.count, 1);
  assert.equal(result.articles?.[0].id, 'otx-pulse-abc123');
  assert.equal(result.articles?.[0].cveIds[0], 'CVE-2026-12345');
  assert.match(result.articles?.[0].summary || '', /ransomware/);
  assert.deepEqual(result.articles?.[0].sourceFeeds, [source.id]);
});

test('OTX ingestion follows only safe same-endpoint pagination URLs', async () => {
  const requested: string[] = [];
  const result = await ingestFeed(source, 48, async (rawUrl) => {
    requested.push(rawUrl);
    if (requested.length === 1) {
      return {
        status: 200,
        body: JSON.stringify({
          results: [pulse('page1', 'First pulse')],
          next: `${OTX_SUBSCRIBED_PULSES_URL}?page=2`,
        }),
        headers: {},
      };
    }
    return {
      status: 200,
      body: JSON.stringify({ results: [pulse('page2', 'Second pulse')], next: null }),
      headers: {},
    };
  }, config, sleep);

  assert.equal(requested.length, 2);
  assert.equal(new URL(requested[1]).searchParams.get('page'), '2');
  assert.equal(new URL(requested[1]).searchParams.get('limit'), '100');
  assert.equal(result.count, 2);
  assert.throws(
    () => validateOtxNextUrl('https://example.com/api/v1/pulses/subscribed/', OTX_SUBSCRIBED_PULSES_URL),
    /invalid pagination URL/,
  );
});

test('OTX pulse pages reject malformed provider data', () => {
  assert.throws(() => parseOtxPulsePage({ results: [{}], next: null }, source.id, 0), /malformed pulse/);
  assert.throws(
    () => validateOtxNextUrl('https://example.com/api/v1/pulses/subscribed/', OTX_SUBSCRIBED_PULSES_URL),
    /invalid pagination URL/,
  );
});
