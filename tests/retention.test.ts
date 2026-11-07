import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  RETENTION_KINDS,
  selectRetention,
  type RetentionPolicy,
  type RetentionRecord,
} from '../server/retention.ts';
import type { RetentionKind } from '../src/types/index.ts';

const NOW = Date.parse('2026-10-24T12:00:00.000Z');
const HOUR = 3_600_000;
const ago = (hours: number) => new Date(NOW - hours * HOUR).toISOString();
const record = (
  kind: RetentionKind,
  id: string,
  timestamp: string | null,
): RetentionRecord => ({ kind, id, timestamp });
const policy = (over: Partial<RetentionPolicy> = {}): RetentionPolicy => ({
  enabled: true,
  retentionHours: 24,
  maxArchivedRecords: 10,
  retentionMode: 'strict',
  ...over,
});
const ids = (plan: ReturnType<typeof selectRetention>) => plan.delete.map((item) => item.id).sort();

test('disabled retention plans no deletions', () => {
  const plan = selectRetention(
    [record('cveData', 'ancient', ago(10_000)), record('emailLogs', 'recent', ago(1))],
    policy({ enabled: false }),
    NOW,
  );
  assert.deepEqual(plan.delete, []);
  assert.equal(plan.cutoff, new Date(NOW - 24 * HOUR).toISOString());
  assert.equal(plan.scanned, 2);
  assert.deepEqual(plan.byKind, Object.fromEntries(RETENTION_KINDS.map((kind) => [kind, 0])));
});

test('strict mode deletes only data older than the window and keeps the boundary', () => {
  const plan = selectRetention(
    [
      record('cveData', 'old', ago(25)),
      record('cveData', 'boundary', ago(24)),
      record('cveData', 'recent', ago(2)),
      record('intelligenceArticles', 'news-old', ago(48)),
      record('executions', 'run-old', ago(30)),
    ],
    policy({ retentionMode: 'strict' }),
    NOW,
  );
  assert.deepEqual(ids(plan), ['news-old', 'old', 'run-old']);
  assert.equal(plan.byKind.cveData, 1);
  assert.equal(plan.byKind.intelligenceArticles, 1);
  assert.equal(plan.byKind.executions, 1);
  assert.equal(plan.byKind.emailLogs, 0);
});

test('records with missing or unparseable timestamps are never deleted', () => {
  const plan = selectRetention(
    [
      record('emailLogs', 'missing', null),
      record('emailLogs', 'blank', ''),
      record('emailLogs', 'garbage', 'not-a-date'),
      record('emailLogs', 'expired', ago(72)),
    ],
    policy(),
    NOW,
  );
  assert.deepEqual(ids(plan), ['expired']);
  assert.equal(plan.unknownAge, 3);
});

test('rolling mode trims the oldest survivors down to the archive ceiling', () => {
  const plan = selectRetention(
    [
      record('cveData', 'expired-new', ago(25)),
      record('cveData', 'expired-old', ago(40)),
      record('cveData', 'survivor-10h', ago(10)),
      record('cveData', 'survivor-8h', ago(8)),
      record('cveData', 'survivor-6h', ago(6)),
      record('cveData', 'survivor-4h', ago(4)),
      record('cveData', 'unknown', null),
    ],
    policy({ retentionMode: 'rolling', maxArchivedRecords: 3 }),
    NOW,
  );
  assert.deepEqual(ids(plan), ['expired-new', 'expired-old', 'survivor-10h']);
  // The undatable record is protected instead of being counted against the cap.
  assert.equal(plan.unknownAge, 1);
});

test('checkpoints mode keeps the newest expired record per UTC day and kind', () => {
  const plan = selectRetention(
    [
      record('cveData', 'day22-early', ago(50)),
      record('cveData', 'day22-late', ago(49)),
      record('cveData', 'day23-early', ago(30)),
      record('cveData', 'day23-late', ago(29)),
      record('cveData', 'boundary', ago(24)),
      record('cveData', 'recent', ago(2)),
      // A checkpoint is kept per kind, so the news record on day 22 survives too.
      record('intelligenceArticles', 'news-day22', ago(50)),
    ],
    policy({ retentionMode: 'checkpoints' }),
    NOW,
  );
  assert.deepEqual(ids(plan), ['day22-early', 'day23-early']);
  assert.equal(plan.byKind.cveData, 2);
  assert.equal(plan.byKind.intelligenceArticles, 0);
});

test('strict mode ignores the archive ceiling and invalid windows delete nothing', () => {
  const records = [
    record('cveData', 'a', ago(1)),
    record('cveData', 'b', ago(2)),
    record('cveData', 'c', ago(3)),
  ];
  assert.deepEqual(
    selectRetention(records, policy({ maxArchivedRecords: 1 }), NOW).delete,
    [],
  );
  const invalid = selectRetention(records, policy({ retentionHours: 0 }), NOW);
  assert.deepEqual(invalid.delete, []);
});

test('audit history is excluded because hash-chain integrity depends on retained links', () => {
  assert.ok(!(RETENTION_KINDS as readonly string[]).includes('auditLogs'));
});

test('intelligenceMatches is retention-eligible with the other transient kinds', () => {
  // Audit P-10: matches were never swept, so the record kind grew without bound
  // and a failed run left stale evidence visible with no owner to clear it.
  assert.ok(
    (RETENTION_KINDS as readonly string[]).includes('intelligenceMatches'),
    'matches must participate in retention',
  );
  const plan = selectRetention(
    [
      record('intelligenceMatches', 'stale-match', ago(72)),
      record('intelligenceMatches', 'fresh-match', ago(1)),
    ],
    policy(),
    NOW,
  );
  assert.deepEqual(ids(plan), ['stale-match']);
  assert.equal(plan.byKind.intelligenceMatches, 1);
});

test('rolling mode trims aged matches like every other kind', () => {
  const plan = selectRetention(
    [
      record('intelligenceMatches', 'match-1', ago(70)),
      record('intelligenceMatches', 'match-2', ago(69)),
      record('intelligenceMatches', 'match-3', ago(68)),
    ],
    // All three are inside a wide window but beyond the archive ceiling.
    policy({ retentionHours: 24 * 365, maxArchivedRecords: 1, retentionMode: 'rolling' }),
    NOW,
  );
  assert.deepEqual(ids(plan), ['match-1', 'match-2']);
});
