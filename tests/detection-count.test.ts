import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Finding } from '../src/types/index.ts';
import { countNewFindings, findingIdentity } from '../src/engine/reconcileFindings.ts';

const finding = (cveId: string, matchedAssetId: string): Finding =>
  ({ cveId, matchedAssetId }) as Finding;

test('countNewFindings counts candidates that were not already known', () => {
  const existing = [finding('CVE-2026-0001', 'asset-a')];
  const candidates = [
    finding('CVE-2026-0001', 'asset-a'),
    finding('CVE-2026-0002', 'asset-a'),
    finding('CVE-2026-0002', 'asset-b'),
  ];
  assert.equal(countNewFindings(existing, candidates), 2);
});

test('countNewFindings returns zero when a run only re-derives current matches', () => {
  const existing = [finding('CVE-2026-0001', 'asset-a'), finding('CVE-2026-0002', 'asset-b')];
  const candidates = [finding('CVE-2026-0001', 'asset-a'), finding('CVE-2026-0002', 'asset-b')];
  assert.equal(countNewFindings(existing, candidates), 0);
});

test('countNewFindings counts each new identity once per run', () => {
  const candidates = [finding('CVE-2026-0001', 'asset-a'), finding('CVE-2026-0001', 'asset-a')];
  assert.equal(countNewFindings([], candidates), 1);
});

test('findingIdentity normalizes CVE spellings but keeps the asset boundary', () => {
  assert.equal(findingIdentity(finding('cve-2026-0001', 'asset-a')), 'CVE-2026-0001:asset-a');
  assert.notEqual(findingIdentity(finding('CVE-2026-0001', 'asset-a')), findingIdentity(finding('CVE-2026-0001', 'asset-b')));
});
