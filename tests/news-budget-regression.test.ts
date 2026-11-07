import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderConsolidatedNewsEmailWithin, type ConsolidatedNewsItem } from '../server/newsEmail.ts';

const one: ConsolidatedNewsItem = {
  article: {
    id: 'article-1', title: 'One incident', url: 'https://example.com/one',
    publishedDate: '2026-11-07T00:00:00Z', modifiedDate: '2026-11-07T00:00:00Z',
    sourceFeeds: ['RSS'], cveIds: [],
  },
  assets: ['server-1'], cveIds: [], evidence: ['Inventory correlation'],
  zeroDay: false, matchIds: ['m1'],
};

test('consolidated news remains a styled HTML document', () => {
  const document = renderConsolidatedNewsEmailWithin([one]);
  assert.match(document.html, /One incident/);
  assert.match(document.html, /color:/);
  assert.equal(document.overflow.length, 0);
});

test('oversized consolidated news fails closed before queueing', () => {
  assert.throws(() => renderConsolidatedNewsEmailWithin([one], 16), /exceeds the allowed size/);
});
