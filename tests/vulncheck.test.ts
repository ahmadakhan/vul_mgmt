import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ingestFeed } from '../server/ingestion';
import { loadConfig } from '../server/config.ts';
import { encrypt } from '../server/secrets.ts';
import type { ThreatFeed } from '../src/types/index.ts';
const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: 'postgres://unused', APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: randomBytes(32).toString('base64') });
const source: ThreatFeed = { id: 'vulncheck', name: 'VulnCheck', type: 'VULNCHECK_KEV', url: 'https://api.vulncheck.com/v3/index/vulncheck-kev', authType: 'BEARER',   authSecretKey: encrypt('test-token', [config.ENCRYPTION_KEY], 'feed:vulncheck'), enabled: true, rateLimitPerMin: 60, healthStatus: 'UNTESTED', lastSync: null, itemCountLastRun: 0, latencyMs: 0, vendorSeed: false, ssrfValidated: false };
const response = (data: unknown) => ({ status: 200, headers: {}, body: JSON.stringify(data) });
const sleep = async () => {};
test('VulnCheck retains different CVEs sharing a date and deduplicates overlapping records across pages', async () => {
  let calls = 0;
  const result = await ingestFeed({ ...source, url: source.url + '?start_cursor=stale&cursor=stale&page=7' }, 24, async raw => {
    calls++;
    const url = new URL(raw);
    assert.equal(url.searchParams.has('page'), false);
    if (calls === 1) {
      assert.equal(url.searchParams.get('start_cursor'), '');
      assert.equal(url.searchParams.has('cursor'), false);
      return response({ data: [
        { cve: ['CVE-2026-10001'], date_added: '2026-10-22' },
        { cve: ['CVE-2026-10002'], date_added: '2026-10-22' },
        { cve: ['CVE-2026-10001'], date_added: '2026-10-22' },
      ], _meta: { next_cursor: 'next' } });
    }
    assert.equal(url.searchParams.has('start_cursor'), false);
    assert.equal(url.searchParams.get('cursor'), 'next');
    return response({ data: [
      { id: 'shared', source: { cve: [' cve-2026-10001 ', 'CVE-2026-10003'] } },
      { id: 'shared', source: { cve: ['CVE-2026-10002'] } },
    ], _meta: { next_cursor: '' } });
  }, config, sleep);
  assert.equal(calls, 2);
  assert.equal(result.count, 3);
  assert.deepEqual(result.exploited, { 'CVE-2026-10001': true, 'CVE-2026-10002': true, 'CVE-2026-10003': true });
});
test('VulnCheck detects immediate and longer pagination cursor loops', async () => {
  for (const cursors of [['a', 'a'], ['a', 'b', 'a']]) {
    let calls = 0;
    await assert.rejects(ingestFeed(source, 24, async () => response({ data: [{ cve: ['CVE-2026-10001'] }], _meta: { next_cursor: cursors[calls++] } }), config, sleep), /cursor did not advance/);
    assert.equal(calls, cursors.length);
  }
});
test('VulnCheck rejects malformed CVE records instead of committing partial exploitation data', async () => {
  await assert.rejects(ingestFeed(source, 24, async () => response({ data: [{ cve: ['CVE-2026-10001'] }, { cve: ['invalid'] }] }), config, sleep), /invalid CVE identifier/);
  await assert.rejects(ingestFeed(source, 24, async () => response({ data: [{ cve: 'CVE-2026-10001' }] }), config, sleep), /no CVE identifiers/);
});
test('VulnCheck requests bounded pages filtered from its committed change checkpoint', async () => {
  const cursor = new Date(Date.now() - 3600000).toISOString();
  const result = await ingestFeed(source, 2880, async raw => {
    const url = new URL(raw);
    assert.equal(url.searchParams.get('limit'), '100');
    assert.equal(url.searchParams.get('lastModStartDate'), new Date(Date.parse(cursor) - 600000).toISOString().slice(0, 10));
    assert.ok(url.searchParams.get('lastModEndDate'));
    return response({ data: [], _meta: {} });
  }, config, sleep, [], undefined, { cursor });
  assert.ok(Date.parse(result.syncState!.cursor!) >= Date.parse(cursor));
  await assert.rejects(ingestFeed(source, 24, async () => response({ data: Array.from({ length: 101 }, () => ({ cve: ['CVE-2026-10001'] })) }), config, sleep), /requested page size/);
});
