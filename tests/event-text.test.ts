import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatEventContext, humanizeEventKey } from '../src/utils/eventText.ts';

test('humanizes camelCase, snake_case and acronym keys', () => {
  assert.equal(humanizeEventKey('workerEnabled'), 'Worker Enabled');
  assert.equal(humanizeEventKey('rawIngested'), 'Raw Ingested');
  assert.equal(humanizeEventKey('cveId'), 'CVE ID');
  assert.equal(humanizeEventKey('error_type'), 'Error Type');
  assert.equal(humanizeEventKey('HTTPStatus'), 'HTTP Status');
  assert.equal(humanizeEventKey('apiKey'), 'API Key');
  assert.equal(humanizeEventKey(''), '');
});

test('renders flat context as labelled text', () => {
  assert.equal(
    formatEventContext({
      workerEnabled: true,
      errorType: 'Error',
      retryCount: 3,
      note: null,
    }),
    ['Worker Enabled: Yes', 'Error Type: Error', 'Retry Count: 3', 'Note: none'].join('\n'),
  );
});

test('indents nested objects and preserves the hierarchy', () => {
  assert.equal(
    formatEventContext({
      component: 'pipeline',
      stats: { rawIngested: 10, matchedWatchlist: 2 },
    }),
    [
      'Component: pipeline',
      'Stats:',
      '  Raw Ingested: 10',
      '  Matched Watchlist: 2',
    ].join('\n'),
  );
});

test('renders scalar arrays inline and object arrays as bullets', () => {
  assert.equal(
    formatEventContext({ errors: ['timeout', 'retry'] }),
    'Errors: timeout, retry',
  );
  assert.equal(
    formatEventContext({
      targets: [
        { cveId: 'CVE-2026-0001', score: 9.8 },
        { cveId: 'CVE-2026-0002' },
      ],
    }),
    [
      'Targets:',
      '  - CVE ID: CVE-2026-0001',
      '    Score: 9.8',
      '  - CVE ID: CVE-2026-0002',
    ].join('\n'),
  );
});

test('keeps multiline values attached to their label', () => {
  assert.equal(
    formatEventContext({ error: 'connection refused\n  at connect (db.ts:42)' }),
    ['Error: connection refused', '    at connect (db.ts:42)'].join('\n'),
  );
  assert.equal(
    formatEventContext({ logs: ['started\nwarming cache'] }),
    ['Logs:', '  - started', '    warming cache'].join('\n'),
  );
});

test('marks empty containers instead of printing braces or brackets', () => {
  assert.equal(
    formatEventContext({ meta: {}, tags: [] }),
    ['Meta: none', 'Tags: none'].join('\n'),
  );
});

test('falls back to a readable placeholder for empty or missing context', () => {
  const empty = 'No additional details recorded.';
  assert.equal(formatEventContext({}), empty);
  assert.equal(formatEventContext([]), empty);
  assert.equal(formatEventContext(null), empty);
  assert.equal(formatEventContext(undefined), empty);
});

test('accepts non-object context values', () => {
  assert.equal(formatEventContext('plain failure'), 'plain failure');
  assert.equal(formatEventContext(42), '42');
  assert.equal(formatEventContext([{ component: 'worker' }]), '- Component: worker');
});

test('output contains no JSON punctuation artefacts', () => {
  const text = formatEventContext({
    nested: { list: [{ key: 'value' }] },
    message: 'failed',
  });
  assert.ok(!/[{}[\]]/.test(text), `unexpected JSON punctuation in: ${text}`);
  assert.ok(!text.includes('":"'), `unexpected JSON key/value syntax in: ${text}`);
});
