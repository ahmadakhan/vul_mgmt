import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Finding } from '../src/types/index.ts';
import { compareFindingsByRecency } from '../src/utils/findingSort.ts';

// The comparator only inspects a finding's CVE dates and identity, so a minimal
// shape is enough to exercise it without a database.
const mk = (cveId: string, id: string, published: string, modified: string): Finding =>
  ({
    id,
    cveId,
    cve: { cveId, publishedDate: published, modifiedDate: modified },
  }) as Finding;

test('compareFindingsByRecency ranks by the newest of published and modified dates', () => {
  // a: published long ago, modified recently -> latest activity is the modified date
  const a = mk('CVE-2026-0001', 'f-a', '2020-01-01T00:00:00Z', '2026-10-26T12:00:00Z');
  // b: published recently, modified long ago -> latest activity is the published date
  const b = mk('CVE-2026-0002', 'f-b', '2026-10-26T10:00:00Z', '2020-01-01T00:00:00Z');

  // a's latest activity (12:00) is newer than b's latest (10:00), so a wins even
  // though a's published date is older than b's published date.
  assert.equal(compareFindingsByRecency(a, b), -1);
  assert.equal(compareFindingsByRecency(b, a), 1);
});

test('compareFindingsByRecency falls back to CVE id then finding id on ties', () => {
  const a = mk('CVE-2026-0001', 'f-a', '2026-10-26T12:00:00Z', '2026-10-26T12:00:00Z');
  const b = mk('CVE-2026-0002', 'f-b', '2026-10-26T12:00:00Z', '2026-10-26T12:00:00Z');
  // Equal latest activity -> deterministic ascending CVE id order.
  assert.equal(compareFindingsByRecency(a, b), -1);
  assert.equal(compareFindingsByRecency(b, a), 1);
  assert.equal(compareFindingsByRecency(a, a), 0);
});

test('compareFindingsByRecency treats unparseable dates as the oldest activity', () => {
  const recent = mk('CVE-2026-0002', 'f-b', '2026-10-26T10:00:00Z', '2000-01-01T00:00:00Z');
  const invalid = mk('CVE-2026-0001', 'f-a', 'not-a-date', 'also-not-a-date');
  // The invalid-dated finding is older than the recent one.
  assert.equal(compareFindingsByRecency(recent, invalid), -1);
  assert.equal(compareFindingsByRecency(invalid, recent), 1);
});
