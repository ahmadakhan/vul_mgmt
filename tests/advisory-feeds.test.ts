import { randomBytes } from 'node:crypto';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadConfig } from '../server/config.ts';
import {
  GITHUB_ADVISORIES_URL,
  OSV_QUERY_BATCH_URL,
  parseGitHubAdvisories,
  parseOsvVulnerability,
} from '../server/advisoryFeeds.ts';
import { ingestFeed } from '../server/ingestion.ts';
import { feedSchema } from '../server/validation.ts';
import type { ThreatFeed } from '../src/types/index.ts';

const config = loadConfig({
  NODE_ENV: 'test',
  DATABASE_URL: 'postgres://unused',
  APP_ORIGIN: 'http://localhost',
  ENCRYPTION_KEY: randomBytes(32).toString('base64'),
});
const feed = (type: 'OSV_API' | 'GITHUB_ADVISORIES'): ThreatFeed => ({
  id: type === 'OSV_API' ? 'feed-osv' : 'feed-github-advisories',
  name: type === 'OSV_API' ? 'OSV' : 'GitHub Advisories',
  type,
  url: type === 'OSV_API' ? OSV_QUERY_BATCH_URL : GITHUB_ADVISORIES_URL,
  authType: 'NONE',
  rateLimitPerMin: 60,
  enabled: true,
  healthStatus: 'UNTESTED',
  lastSync: null,
  latencyMs: 0,
  itemCountLastRun: 0,
  ssrfValidated: false,
  vendorSeed: true,
});
const now = new Date();
const current = now.toISOString();
const previous = new Date(now.getTime() - 60_000).toISOString();
const sleep = async () => {};
const osv = (overrides = {}) => ({
  id: 'GHSA-8v4x-mgvp-p658',
  aliases: ['CVE-2026-12345'],
  summary: 'Example library vulnerability',
  details: 'An example vulnerability in the package.',
  published: previous,
  modified: current,
  references: [{ type: 'ADVISORY', url: 'https://osv.dev/vulnerability/GHSA-8v4x-mgvp-p658' }],
  ...overrides,
});
const github = (overrides = {}) => ({
  ghsa_id: 'GHSA-8v4x-mgvp-p658',
  cve_id: 'CVE-2026-12345',
  html_url: 'https://github.com/advisories/GHSA-8v4x-mgvp-p658',
  summary: 'Example GitHub advisory',
  description: 'An example advisory description.',
  severity: 'high',
  cvss: { score: 8.1, vector_string: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N' },
  cwes: [{ cwe_id: 'CWE-79' }],
  identifiers: [{ type: 'CVE', value: 'CVE-2026-12345' }],
  references: ['https://example.com/advisory'],
  published_at: previous,
  updated_at: current,
  withdrawn_at: null,
  ...overrides,
});

test('new API feed types validate only their official public endpoints', () => {
  for (const [type, url] of [
    ['OSV_API', OSV_QUERY_BATCH_URL],
    ['GITHUB_ADVISORIES', GITHUB_ADVISORIES_URL],
  ] as const) {
    assert.equal(feedSchema.safeParse({
      name: type,
      type,
      url,
      authType: 'NONE',
      rateLimitPerMin: 10,
      enabled: true,
    }).success, true);
    assert.equal(feedSchema.safeParse({
      name: type,
      type,
      url: 'https://example.com/',
      authType: 'NONE',
      rateLimitPerMin: 10,
      enabled: true,
    }).success, false);
  }
});

test('OSV ingestion queries only versioned active inventory PURLs and scopes CVEs to matched packages', async () => {
  const calls: { url: string; method?: string; body?: string }[] = [];
  const result = await ingestFeed(feed('OSV_API'), 24, async (url, options) => {
    calls.push({ url, method: options?.method, body: options?.body });
    if (url === OSV_QUERY_BATCH_URL) {
      assert.equal(options?.method, 'POST');
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-8v4x-mgvp-p658', modified: current }] }] }),
      };
    }
    return { status: 200, headers: {}, body: JSON.stringify(osv()) };
  }, config, sleep, [], undefined, {
    targetPurls: ['pkg:npm/example@1.2.3', 'pkg:npm/no-version', 'pkg:npm/example@1.2.3'],
  });

  assert.equal(calls.length, 2);
  assert.deepEqual(JSON.parse(calls[0].body!).queries, [{ package: { purl: 'pkg:npm/example@1.2.3' } }]);
  assert.equal(result.count, 1);
  assert.equal(result.cves[0].cveId, 'CVE-2026-12345');
  assert.deepEqual(result.cves[0].purls, ['pkg:npm/example@1.2.3']);
  assert.deepEqual(result.cves[0].sourceFeeds, ['feed-osv']);
});

test('OSV pages through querybatch results and retains standalone GHSA advisories', async () => {
  const requests: string[] = [];
  const result = await ingestFeed(feed('OSV_API'), 24, async (url, options) => {
    requests.push(url);
    if (url === OSV_QUERY_BATCH_URL) {
      const body = JSON.parse(options?.body || '{}');
      if (body.queries[0].page_token) {
        assert.equal(body.queries[0].page_token, 'continue-1');
        return {
          status: 200,
          headers: {},
          body: JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-2345-6789-2345', modified: current }] }] }),
        };
      }
      return {
        status: 200,
        headers: {},
        body: JSON.stringify({ results: [{
          vulns: [{ id: 'GHSA-8v4x-mgvp-p658', modified: current }],
          next_page_token: 'continue-1',
        }] }),
      };
    }
    const id = decodeURIComponent(new URL(url).pathname.split('/').pop() || '');
    return {
      status: 200,
      headers: {},
      body: JSON.stringify(osv({ id, aliases: id === 'GHSA-2345-6789-2345' ? [] : ['CVE-2026-12345'] })),
    };
  }, config, sleep, [], undefined, { targetPurls: ['pkg:npm/example@1.2.3'] });

  assert.equal(requests.length, 4);
  assert.equal(result.articles?.[0].id, 'osv-GHSA-2345-6789-2345');
});

test('GitHub advisories are paged and normalized as CVEs or standalone articles', async () => {
  const requested: URL[] = [];
  const result = await ingestFeed(feed('GITHUB_ADVISORIES'), 24, async (rawUrl, options) => {
    const url = new URL(rawUrl);
    requested.push(url);
    assert.equal(options?.headers?.accept, 'application/vnd.github+json');
    assert.equal(url.searchParams.get('per_page'), '100');
    return {
      status: 200,
      headers: {},
      body: JSON.stringify([
        github(),
        github({
          ghsa_id: 'GHSA-2345-6789-2345',
          cve_id: null,
          identifiers: [{ type: 'GHSA', value: 'GHSA-2345-6789-2345' }],
        }),
      ]),
    };
  }, config, sleep);

  assert.equal(requested.length, 1);
  assert.equal(requested[0].searchParams.get('sort'), 'updated');
  assert.equal(result.cves[0].cveId, 'CVE-2026-12345');
  assert.equal(result.cves[0].cvss.severity, 'HIGH');
  assert.equal(result.articles?.[0].id, 'ghsa-2345-6789-2345');
  assert.ok(result.syncState?.cursor);
});

test('GitHub global advisories follow only the API-provided same-endpoint cursor', async () => {
  const requested: URL[] = [];
  const result = await ingestFeed(feed('GITHUB_ADVISORIES'), 24, async (rawUrl) => {
    const url = new URL(rawUrl);
    requested.push(url);
    const records = requested.length === 1
      ? Array.from({ length: 100 }, (_, index) => github({
          cve_id: `CVE-2026-${String(20000 + index)}`,
          identifiers: [{ type: 'CVE', value: `CVE-2026-${String(20000 + index)}` }],
        }))
      : [github({ cve_id: 'CVE-2026-30000', identifiers: [{ type: 'CVE', value: 'CVE-2026-30000' }] })];
    return {
      status: 200,
      headers: requested.length === 1
        ? { link: '<https://api.github.com/advisories?after=cursor-one>; rel="next"' }
        : {},
      body: JSON.stringify(records),
    };
  }, config, sleep);

  assert.equal(requested.length, 2);
  assert.equal(requested[1].searchParams.get('after'), 'cursor-one');
  assert.equal(result.cves.length, 101);
});

test('GitHub global advisories reject a repeated pagination cursor', async () => {
  let requests = 0;
  await assert.rejects(ingestFeed(feed('GITHUB_ADVISORIES'), 24, async () => {
    requests++;
    return {
      status: 200,
      headers: { link: '<https://api.github.com/advisories?after=cursor-one>; rel="next"' },
      body: JSON.stringify([github()]),
    };
  }, config, sleep), /repeated a pagination cursor/);
  assert.equal(requests, 2);
});

test('GitHub global advisories stop at the ten-page run bound', async () => {
  let requests = 0;
  await assert.rejects(ingestFeed(feed('GITHUB_ADVISORIES'), 24, async () => {
    requests++;
    return {
      status: 200,
      headers: { link: `<https://api.github.com/advisories?after=cursor-${requests}>; rel="next"` },
      body: '[]',
    };
  }, config, sleep), /ten-page ingestion bound/);
  assert.equal(requests, 10);
});

test('advisory parsers reject malformed records and preserve withdrawal data', () => {
  assert.throws(() => parseOsvVulnerability({ ...osv(), modified: 'not-a-date' }, 'osv', []), /Invalid OSV modified timestamp/);
  assert.throws(() => parseGitHubAdvisories([github({ ghsa_id: 'not-ghsa' })], 'gh', new Date(0), now), /ghsa_id/);

  const withdrawnOsv = parseOsvVulnerability(osv({ withdrawn: current }), 'osv', []);
  assert.deepEqual(withdrawnOsv.withdrawals, [{ cveId: 'CVE-2026-12345', modifiedDate: current }]);
  const withdrawnGithub = parseGitHubAdvisories(
    [github({ withdrawn_at: current })],
    'gh',
    new Date(0),
    new Date(Date.now() + 1_000),
  );
  assert.deepEqual(withdrawnGithub.withdrawals, [{ cveId: 'CVE-2026-12345', modifiedDate: current }]);
});
