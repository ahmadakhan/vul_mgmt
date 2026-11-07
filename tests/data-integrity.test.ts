import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mergeCveRecords } from '../src/utils/deduplicator.ts';
import { reconcileFindings } from '../src/engine/reconcileFindings.ts';
import { idSchema } from '../server/validation.ts';
import type { Finding, NormalizedCVE } from '../src/types/index.ts';
import { INITIAL_NORMALIZED_CVES } from './fixtures/seedData';

const cve = (id: string, modifiedDate: string, title: string): NormalizedCVE => ({
  ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
  cveId: id,
  modifiedDate,
  title,
});

const finding = (id: string, cveId: string, evidence: string): Finding => ({
  id,
  cveId,
  cve: cve(cveId, '2026-10-25T00:00:00.000Z', evidence),
  matchedAssetId: 'asset-1',
  matchedAssetName: 'Widget',
  matchedCpe: 'cpe:2.3:a:example:widget:1.5:*:*:*:*:*:*:*',
  matchingMethod: 'CPE_EXACT',
  matchingEvidence: evidence,
  exploitRisk: 'STANDARD',
  notificationStatus: 'QUEUED_FOR_DISPATCH',
  status: 'MONITORED',
  autoDispatchedAt: null,
  advisoryId: null,
  reviewNotifiedAt: null,
  timeline: [],
});

test('an unparseable revision date cannot make a stale record win a merge', () => {
  const stale = cve('CVE-2026-81001', 'not-a-date', 'stale');
  const fresh = cve('CVE-2026-81001', '2026-10-25T00:00:00.000Z', 'fresh');

  assert.equal(mergeCveRecords([stale, fresh]).get('CVE-2026-81001')?.title, 'fresh');
  assert.equal(mergeCveRecords([fresh, stale]).get('CVE-2026-81001')?.title, 'fresh');
});

test('two unparseable revision dates resolve deterministically instead of silently keeping the first', () => {
  const first = cve('CVE-2026-81002', 'invalid', 'alpha');
  const second = cve('CVE-2026-81002', 'invalid', 'zeta');

  assert.equal(mergeCveRecords([first, second]).get('CVE-2026-81002')?.title, 'zeta');
  assert.equal(mergeCveRecords([second, first]).get('CVE-2026-81002')?.title, 'zeta');
});

test('invalid CVE identifiers do not collapse distinct findings onto one identity', () => {
  const first = finding('finding-a', 'not-a-cve-a', 'evidence-a');
  const second = finding('finding-b', 'not-a-cve-b', 'evidence-b');

  const reconciled = reconcileFindings([first, second], [first, second]);
  assert.deepEqual(reconciled.map((item) => item.id).sort(), ['finding-a', 'finding-b']);
  assert.equal(reconciled.find((item) => item.id === 'finding-a')?.matchingEvidence, 'evidence-a');
  assert.equal(reconciled.find((item) => item.id === 'finding-b')?.matchingEvidence, 'evidence-b');
});

test('duplicate candidate identities are deduplicated, keeping the first occurrence', () => {
  const existing: Finding[] = [];
  const dupA = finding('finding-dup-a', 'CVE-2026-82001', 'evidence-first');
  const dupB = finding('finding-dup-b', 'CVE-2026-82001', 'evidence-second');
  const other = finding('finding-other', 'CVE-2026-82002', 'evidence-other');

  const reconciled = reconcileFindings(existing, [dupA, dupB, other]);
  assert.deepEqual(
    reconciled.map((item) => item.id).sort(),
    ['finding-dup-a', 'finding-other'],
  );
  assert.equal(reconciled.length, 2);
  assert.equal(
    reconciled.find((item) => item.matchedAssetId === 'asset-1' && item.cveId === 'CVE-2026-82001')?.id,
    'finding-dup-a',
  );
});

test('identifiers reject control characters but keep legitimate separators', () => {
  assert.equal(idSchema.safeParse('asset-1:production').success, true);
  assert.equal(idSchema.safeParse('bad\u0000id').success, false);
  assert.equal(idSchema.safeParse('bad\nid').success, false);
  assert.equal(idSchema.safeParse('bad\u007fid').success, false);
});
