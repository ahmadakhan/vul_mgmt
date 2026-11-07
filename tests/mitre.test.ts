import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ingestFeed } from '../server/ingestion';
import { normalizeMitre, MITRE_DELTA_URL } from '../server/mitre';
import { loadConfig } from '../server/config.ts';
import { feedSchema, feedImportSchema } from '../server/validation.ts';
import { mergeCveRecords } from '../src/utils/deduplicator';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine';
import { DEFAULT_SETTINGS } from '../shared/state.ts';
import type { ThreatFeed, WatchListItem } from '../src/types/index.ts';
import { mitreRecord, mitreDelta } from './fixtures/mitre';
const config = loadConfig({ NODE_ENV: 'test', DATABASE_URL: 'postgres://unused', APP_ORIGIN: 'http://localhost', ENCRYPTION_KEY: randomBytes(32).toString('base64') });
const source: ThreatFeed = { id: 'mitre', name: 'MITRE CVE', type: 'MITRE_CVE', url: MITRE_DELTA_URL, authType: 'NONE', enabled: true, rateLimitPerMin: 120, healthStatus: 'UNTESTED', lastSync: null, latencyMs: 0, itemCountLastRun: 0, vendorSeed: true, ssrfValidated: false };
const response = (value: unknown) => ({ status: 200, body: JSON.stringify(value), headers: {} });
const sleep = async () => {};

test('MITRE normalizes CVE JSON 5 and keeps uncertain version semantics under review', () => {
  const record = normalizeMitre(mitreRecord(), source.id)!;
  assert.equal(record.cvss.score, 8.1);
  assert.equal(record.cvss.version, '3.1');
  assert.deepEqual(record.cwe, ['CWE-79']);
  assert.equal(record.applicabilityRequiresReview, true);
  assert.equal(record.applicabilityPolicy, 'REVIEW_ONLY');
  assert.deepEqual(record.sourceFeeds, ['mitre']);
  const raw = mitreRecord();
  raw.containers.cna.metrics = [];
  assert.equal(normalizeMitre(raw, 'mitre')!.cvss.severity, 'UNKNOWN');
  assert.throws(() => normalizeMitre({ ...raw, dataVersion: '4.0' }, 'mitre'), /CVE JSON 5/);
});
test('MITRE ingests each canonical CVE once across overlapping delta entries and ignores supplied URLs', async () => {
  const date = new Date(Date.now() - 1000).toISOString();
  const deltas = mitreDelta('cve-2026-98001', date).map(entry => ({ ...entry, new: entry.new.map(row => ({ ...row, githubLink: 'https://127.0.0.1/private' })) }));
  const calls: string[] = [];
  const result = await ingestFeed(source, 24, async (url, options) => {
    calls.push(url);
    assert.ok(options!.maxResponseBytes! > 0);
    return response(url === MITRE_DELTA_URL ? [...deltas, ...deltas] : mitreRecord('CVE-2026-98001', date));
  }, config, sleep);
  assert.deepEqual(calls, [MITRE_DELTA_URL, 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/98xxx/CVE-2026-98001.json']);
  assert.equal(result.count, 1);
  assert.equal(result.cves.length, 1);
});
test('MITRE skips fetching details for revisions already in the canonical cache', async () => {
  const date = new Date(Date.now() - 1000).toISOString();
  const calls: string[] = [];
  const result = await ingestFeed(
    source,
    24,
    async (url) => {
      calls.push(url);
      return response(url === MITRE_DELTA_URL ? mitreDelta('CVE-2026-98001', date) : mitreRecord('CVE-2026-98001', date));
    },
    config,
    sleep,
    [],
    undefined,
    {
      revisions: { 'CVE-2026-98001': date },
      knownCveModifiedAt: new Map([['CVE-2026-98001', new Date(Date.now() + 60_000).toISOString()]]),
    },
  );
  assert.deepEqual(calls, [MITRE_DELTA_URL]);
  assert.equal(result.cves.length, 0);
});
test('a later timestamp from another provider does not suppress a MITRE revision', async () => {
  const date = new Date(Date.now() - 1000).toISOString();
  const laterNvdDate = new Date(Date.now()).toISOString();
  const calls: string[] = [];
  const result = await ingestFeed(
    source,
    24,
    async (url) => {
      calls.push(url);
      return response(url === MITRE_DELTA_URL ? mitreDelta('CVE-2026-98001', date) : mitreRecord('CVE-2026-98001', date));
    },
    config,
    sleep,
    [],
    undefined,
    { knownCveModifiedAt: new Map([['CVE-2026-98001', laterNvdDate]]) },
  );
  assert.equal(result.cves.length, 1);
  assert.equal(calls.length, 2, 'MITRE detail must be fetched despite the newer NVD timestamp');
});
test('MITRE rejects mismatched records and preserves upstream rejection as a withdrawal', async () => {
  const date = new Date(Date.now() - 1000).toISOString();
  const request = async (url: string) => response(url === MITRE_DELTA_URL ? mitreDelta(undefined, date) : mitreRecord('CVE-2026-99999', date));
  await assert.rejects(ingestFeed(source, 24, request, config, sleep), /did not match/);
  const rejected = { ...mitreRecord(undefined, date), cveMetadata: { cveId: 'CVE-2026-98001', state: 'REJECTED', dateUpdated: date } };
  const result = await ingestFeed(source, 24, async url => response(url === MITRE_DELTA_URL ? mitreDelta(undefined, date) : rejected), config, sleep);
  assert.equal(result.cves.length, 0);
  assert.deepEqual(result.withdrawals, [{ cveId: 'CVE-2026-98001', modifiedDate: date }]);
});
test('MITRE source validates official endpoint and imports, reports history limits, excludes old deltas', async () => {
  assert.equal(feedSchema.safeParse({ ...source, url: 'https://example.com/feed' }).success, false);
  assert.equal(feedSchema.safeParse({ ...source, authType: 'BEARER' }).success, false);
  assert.equal(feedImportSchema.parse([source]).length, 1);
  const old = new Date(Date.now() - 40 * 86400000).toISOString();
  let calls = 0;
  const result = await ingestFeed(source, 2880, async () => { calls++; return response(mitreDelta(undefined, old)); }, config, sleep);
  assert.equal(calls, 1);
  assert.equal(result.cves.length, 0);
  assert.match(result.warnings!.join(), /30 days/);
});
test('MITRE and overlapping provider revisions merge into one CVE and one finding per asset', () => {
  const mitre = normalizeMitre(mitreRecord(), 'mitre')!;
  const other = { ...mitre, cveId: ' cve-2026-98001 ', sourceFeeds: ['nvd'] };
  const merged = mergeCveRecords([mitre, other, mitre]);
  assert.equal(merged.size, 1);
  assert.deepEqual(merged.get(mitre.cveId)!.sourceFeeds, ['mitre', 'nvd']);
  const asset: WatchListItem = { id: 'asset', vendor: 'example', product: 'widget', cpes: ['cpe:2.3:a:example:widget:1.5:*:*:*:*:*:*:*'], assetTag: 'TEST', ownerGroup: 'Test', active: true, createdAt: new Date().toISOString() };
  const first = runVulnerabilityPipeline([source], [mitre, other, mitre], [asset], [], [], DEFAULT_SETTINGS);
  assert.equal(first.newFindings.length, 1);
  assert.equal(first.newFindings[0].notificationStatus, 'REVIEW_REQUIRED');
  assert.equal(runVulnerabilityPipeline([source], [...merged.values()], [asset], [], first.newFindings, DEFAULT_SETTINGS).newFindings.length, 0);
});

test('MITRE fails closed on invalid JSON, HTTP failures, upstream errors and oversized windows', async () => {
  await assert.rejects(ingestFeed(source, 24, async () => ({ status: 429, body: '', headers: {} }), config, sleep), /HTTP 429/);
  await assert.rejects(ingestFeed(source, 24, async () => ({ status: 200, body: '{', headers: {} }), config, sleep), /invalid JSON/);
  const date = new Date(Date.now() - 1000).toISOString();
  await assert.rejects(ingestFeed(source, 24, async () => response(mitreDelta(undefined, date).map(entry => ({ ...entry, error: ['upstream failure'] }))), config, sleep), /upstream record errors/);
  const delta = [{ fetchTime: date, new: Array.from({ length: 5001 }, (_, index) => ({ cveId: `CVE-2026-${10000 + index}`, dateUpdated: date })), updated: [] }];
  await assert.rejects(ingestFeed(source, 24, async () => response(delta), config, sleep), /5,000/);
});
test('MITRE does not re-emit a CVE whose timestamp and content are unchanged', async () => {
  const date = new Date(Date.now() - 1000).toISOString();
  const baseline = await ingestFeed(
    source,
    24,
    async (url) =>
      response(url === MITRE_DELTA_URL ? mitreDelta('CVE-2026-98001', date) : mitreRecord('CVE-2026-98001', date)),
    config,
    sleep,
  );
  assert.equal(baseline.cves.length, 1);
  const cached = baseline.cves[0];
  const calls: string[] = [];
  const second = await ingestFeed(
    source,
    24,
    async (url) => {
      calls.push(url);
      return response(url === MITRE_DELTA_URL ? mitreDelta('CVE-2026-98001', date) : mitreRecord('CVE-2026-98001', date));
    },
    config,
    sleep,
    [],
    undefined,
    { knownCveModifiedAt: new Map([['CVE-2026-98001', date]]), knownCveContent: new Map([['CVE-2026-98001', cached]]) },
  );
  assert.equal(second.cves.length, 0, 'unchanged content at an unchanged timestamp must not be re-ingested');
  assert.ok(
    calls.includes('https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/98xxx/CVE-2026-98001.json'),
    'content comparison still fetches the detail to diff against the cache',
  );
});
test('MITRE re-ingests a CVE whose timestamp did not advance but whose content changed', async () => {
  const date = new Date(Date.now() - 1000).toISOString();
  const baseline = await ingestFeed(
    source,
    24,
    async (url) =>
      response(url === MITRE_DELTA_URL ? mitreDelta('CVE-2026-98001', date) : mitreRecord('CVE-2026-98001', date)),
    config,
    sleep,
  );
  assert.equal(baseline.cves.length, 1);
  const cached = baseline.cves[0];
  // Same dateUpdated (timestamp does not advance), but the description changed.
  const corrected = mitreRecord('CVE-2026-98001', date);
  corrected.containers.cna.descriptions = [
    { lang: 'en', value: 'corrected remediation without a timestamp advance' },
  ];
  const second = await ingestFeed(
    source,
    24,
    async (url) =>
      response(url === MITRE_DELTA_URL ? mitreDelta('CVE-2026-98001', date) : corrected),
    config,
    sleep,
    [],
    undefined,
    { knownCveModifiedAt: new Map([['CVE-2026-98001', date]]), knownCveContent: new Map([['CVE-2026-98001', cached]]) },
  );
  assert.equal(second.cves.length, 1, 'a content correction without a timestamp advance must be re-ingested');
  assert.equal(second.count, 1);
});
