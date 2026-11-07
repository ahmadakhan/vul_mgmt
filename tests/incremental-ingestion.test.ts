import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ingestionWindow, SYNC_OVERLAP_MS, OPENCVE_MAX_WINDOW_HOURS } from '../server/ingestionState';
import { ingestFeed } from '../server/ingestion';
import { MITRE_DELTA_URL } from '../server/mitre';
import { loadConfig } from '../server/config.ts';
import { encrypt } from '../server/secrets.ts';
import type { ThreatFeed } from '../src/types/index.ts';
import { mitreDelta, mitreRecord } from './fixtures/mitre';
const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: 'postgres://unused', APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: randomBytes(32).toString('base64') });
const feed = (type: ThreatFeed['type']): ThreatFeed => ({ id: 'source', name: 'Source', type, url: type === 'MITRE_CVE' ? MITRE_DELTA_URL : 'https://example.com/cves', authType: 'NONE', rateLimitPerMin: 600, enabled: true, healthStatus: 'UNTESTED', lastSync: null, itemCountLastRun: 0, latencyMs: 0, vendorSeed: false, ssrfValidated: false });
const response = (data: unknown) => ({ status: 200, body: JSON.stringify(data), headers: { etag: 'index-v1' } });
const sleep = async () => {};

test('RSS ingestion identifies the real reader and preserves conditional fetches', async () => {
  const source = { ...feed('RSS_ATOM'), url: 'https://www.bleepingcomputer.com/feed/', etag: 'rss-v1' };
  const result = await ingestFeed(source, 24, async (url, options) => {
    assert.equal(url, source.url);
    assert.equal(options?.headers?.['user-agent'], 'VulnStream/1.0 RSS reader');
    assert.match(options!.headers!.accept, /application\/rss\+xml/);
    assert.equal(options?.headers?.['If-None-Match'], 'rss-v1');
    return {
      status: 200,
      body: `<rss version="2.0"><channel><title>Security News</title><item><title>Security update</title><link>https://www.bleepingcomputer.com/news/security/example/</link><pubDate>${new Date().toUTCString()}</pubDate></item></channel></rss>`,
      headers: { etag: 'rss-v2' },
    };
  }, config, sleep);
  assert.equal(result.articles?.length, 1);
  assert.equal(result.etag, 'rss-v2');
  await assert.rejects(ingestFeed(source, 24, async () => ({ status: 403, body: '<html>Forbidden</html>', headers: {} }), config, sleep), /HTTP 403/);
});

test('bootstrap is bounded and checkpoints catch up without gaps in bounded daily windows', () => {
  const now = Date.parse('2026-10-22T00:00:00Z');
  assert.equal(now - ingestionWindow(2880, {}, now).start.getTime(), 24 * 3600000);
  const checkpoint = now - 72 * 3600000;
  const window = ingestionWindow(24, { cursor: new Date(checkpoint).toISOString() }, now);
  assert.equal(window.start.getTime(), checkpoint - SYNC_OVERLAP_MS);
  assert.equal(window.end.getTime() - window.start.getTime(), 24 * 3600000);
  assert.equal(window.hasMore, true);
  assert.equal(ingestionWindow(24, { cursor: new Date(now + 3600000).toISOString() }, now).incremental, false);
});
test('OpenCVE uses a reduced incremental window cap to stay under the 500-CVE limit', () => {
  const now = Date.parse('2026-10-22T00:00:00Z');
  const checkpoint = now - 72 * 3600000;
  const window = ingestionWindow(2880, { cursor: new Date(checkpoint).toISOString() }, now, OPENCVE_MAX_WINDOW_HOURS);
  assert.equal(window.start.getTime(), checkpoint - SYNC_OVERLAP_MS);
  assert.equal(window.end.getTime() - window.start.getTime(), OPENCVE_MAX_WINDOW_HOURS * 3600000);
  assert.equal(window.incremental, true);
});
test('NVD requests only changes since its checkpoint and reports the frozen end watermark', async () => {
  const cursor = new Date(Date.now() - 3600000).toISOString();
  let end = '';
  const result = await ingestFeed(feed('NVD_API'), 2880, async raw => {
    const url = new URL(raw);
    assert.equal(url.searchParams.get('lastModStartDate'), new Date(Date.parse(cursor) - SYNC_OVERLAP_MS).toISOString());
    end = url.searchParams.get('lastModEndDate')!;
    return response({ startIndex: 0, totalResults: 0, vulnerabilities: [] });
  }, config, sleep, [], undefined, { cursor });
  assert.equal(result.syncState!.cursor, end);
  assert.equal(result.count, 0);
});
test('MITRE skips unchanged record revisions and uses conditional requests for an unchanged index', async () => {
  const date = new Date(Date.now() - 1000).toISOString();
  let records = 0;
  const request = async (url: string) => {
    if (url === MITRE_DELTA_URL) return response(mitreDelta(undefined, date));
    records++; return response(mitreRecord(undefined, date));
  };
  const first = await ingestFeed(feed('MITRE_CVE'), 24, request, config, sleep);
  assert.equal(records, 1);
  const second = await ingestFeed(feed('MITRE_CVE'), 24, request, config, sleep, [], undefined, first.syncState);
  assert.equal(records, 1);
  assert.equal(second.count, 0);
  const unchanged = await ingestFeed(feed('MITRE_CVE'), 24, async (_url, options) => {
    assert.equal(options!.headers!['If-None-Match'], 'index-v1');
    return { status: 304, body: '', headers: {} };
  }, config, sleep, [], undefined, second.syncState);
  assert.equal(unchanged.notModified, true);
  assert.deepEqual(unchanged.syncState, second.syncState);
});
test('MITRE re-fetches revised records and limits concurrent requests while pacing starts', async () => {
  const date = new Date(Date.now() - 1000).toISOString();
  const ids = Array.from({ length: 8 }, (_, n) => `CVE-2026-${98001 + n}`);
  let active = 0, max = 0, waits = 0;
  const source = feed('MITRE_CVE');
  const result = await ingestFeed(source, 24, async url => {
    if (url === MITRE_DELTA_URL) return response([{ fetchTime: date, new: ids.map(cveId => ({ cveId, dateUpdated: date })), updated: [] }]);
    active++; max = Math.max(max, active);
    await new Promise(resolve => setTimeout(resolve, 150));
    active--;
    return response(mitreRecord(url.match(/(CVE-\d{4}-\d+)\.json$/)![1], date));
  }, config, async ms => { assert.ok(ms > 0); waits++; await new Promise(resolve => setTimeout(resolve, ms)); }, [], undefined,
  { cursor: new Date(Date.now() - 3600000).toISOString(), revisions: { [ids[0]]: new Date(Date.now() - 7200000).toISOString() } });
  assert.equal(result.count, 8);
  assert.ok(max <= 3 && max > 1);
  assert.ok(waits >= 7);
});
test('OpenCVE lists changed records but does not fetch unchanged details within the overlap', async () => {
  const source = { ...feed('OPENCVE_API'), authType: 'BEARER' as const, authSecretKey: encrypt('test-token', [config.ENCRYPTION_KEY], 'feed:source') };
  const date = new Date(Date.now() - 1000).toISOString();
  let details = 0;
  const request = async (raw: string) => {
    const url = new URL(raw);
    if (url.pathname.endsWith('/cves')) {
      const query = url.searchParams.get('q') || '';
      assert.match(query, /updated>=\d{4}-\d{2}-\d{2} AND updated<\d{4}-\d{2}-\d{2}/);
      assert.doesNotMatch(query, /updated<=/);
      return response({ count: 1, next: null, results: [{ cve_id: 'CVE-2026-98001', updated_at: date }] });
    }
    details++;
    return response({ cve_id: 'CVE-2026-98001', created_at: date, updated_at: date, description: 'Example vulnerability' });
  };
  const first = await ingestFeed(source, 24, request, config, sleep);
  const second = await ingestFeed(source, 24, request, config, sleep, [], undefined, first.syncState);
  assert.equal(details, 1);
  assert.equal(second.count, 0);
});
test('OpenCVE uses a reduced 3-hour incremental window to stay under the 500-CVE cap', async () => {
  const source = { ...feed('OPENCVE_API'), authType: 'BEARER' as const, authSecretKey: encrypt('test-token', [config.ENCRYPTION_KEY], 'feed:source') };
  const cursorDate = new Date(Date.now() - 60000);
  const date = new Date(Date.now() - 30000).toISOString();
  const request = async (raw: string) => {
    const url = new URL(raw);
    if (url.pathname.endsWith('/cves')) {
      return response({ count: 1, next: null, results: [{ cve_id: 'CVE-2026-98001', updated_at: date }] });
    }
    return response({ cve_id: 'CVE-2026-98001', created_at: date, updated_at: date, description: 'Example vulnerability' });
  };
  const result = await ingestFeed(source, 2880, request, config, sleep, [], undefined, { cursor: cursorDate.toISOString() });
  assert.equal(result.count, 1);
});
test('EPSS reuses recent scores, queries newly matching CVEs, and refreshes on expiry', async () => {
  let calls = 0;
  const request = async (raw: string) => {
    calls++;
    const ids = new URL(raw).searchParams.get('cve')!.split(',');
    return response({ total: ids.length, data: ids.map(cve => ({ cve, epss: '0.1', percentile: '0.5' })) });
  };
  const first = await ingestFeed(feed('EPSS_API'), 24, request, config, sleep, ['CVE-2026-98001']);
  const second = await ingestFeed(feed('EPSS_API'), 24, request, config, sleep, ['CVE-2026-98001'], undefined, first.syncState);
  assert.equal(second.notModified, true);
  assert.equal(calls, 1);
  const third = await ingestFeed(feed('EPSS_API'), 24, request, config, sleep, ['CVE-2026-98001', 'CVE-2026-98002'], undefined, first.syncState);
  assert.deepEqual(third.epssScope, ['CVE-2026-98002']);
  assert.equal(third.syncState!.epssExpiresAt, first.syncState!.epssExpiresAt);
  const expired = { ...third.syncState, epssExpiresAt: new Date(Date.now() - 1000).toISOString() };
  const refreshed = await ingestFeed(feed('EPSS_API'), 24, request, config, sleep, ['CVE-2026-98001', 'CVE-2026-98002'], undefined, expired);
  assert.equal(calls, 3);
  assert.equal(refreshed.epssScope!.length, 2);
});
test('transient response resets retry without advancing a failed source checkpoint', async () => {
  let calls = 0, waits = 0;
  const result = await ingestFeed(feed('NVD_API'), 24, async () => {
    calls++;
    if (calls === 1) throw Object.assign(new Error('aborted'), { code: 'ECONNRESET' });
    return response({ startIndex: 0, totalResults: 0, vulnerabilities: [] });
  }, config, async () => { waits++; });
  assert.equal(calls, 2);
  assert.equal(waits, 1);
  assert.ok(result.syncState!.cursor);
  await assert.rejects(ingestFeed({ ...feed('NVD_API'), authType: 'API_KEY', authSecretKey: 'invalid-encrypted-data' }, 24, async () => { throw new Error('No network expected'); }, config, sleep), /re-enter the secret/);
});
