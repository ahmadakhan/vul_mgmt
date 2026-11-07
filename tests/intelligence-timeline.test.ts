import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchIntelligence } from '../src/utils/intelligenceMatcher.ts';
import { runVulnerabilityPipeline } from '../src/engine/pipelineEngine.ts';
import type { IntelligenceArticle, NormalizedCVE, WatchListItem } from '../src/types/index.ts';
import {
  INITIAL_FEEDS,
  INITIAL_NORMALIZED_CVES,
  INITIAL_SETTINGS,
  INITIAL_WATCHLIST,
} from './fixtures/seedData';

const NOW = new Date('2026-10-26T12:00:00Z');
const ONE_WEEK = 168;

const asset: WatchListItem = {
  id: 'asset-timeline',
  vendor: 'acme',
  product: 'widget',
  version: '2.0',
  cpes: [],
  purls: [],
  assetTag: 'Timeline asset',
  ownerGroup: 'Security',
  active: true,
  createdAt: '2026-01-01T00:00:00Z',
};

const article = (id: string, published: string, modified: string): IntelligenceArticle => ({
  id,
  url: `https://example.com/${id}`,
  title: 'Acme Widget vulnerability',
  summary: 'A vulnerability affects the Acme Widget product.',
  publishedDate: published,
  modifiedDate: modified,
  cveIds: [],
  sourceFeeds: ['news'],
});

test('vendor + product news matching uses the latest of published and modified dates', () => {
  // Published two days before NOW, last modified ten days before NOW.
  const recentlyPublished = article('recent-published', '2026-10-24T12:00:00Z', '2026-10-16T12:00:00Z');
  // Published ten days before NOW, last modified two days before NOW.
  const recentlyModified = article('recent-modified', '2026-10-16T12:00:00Z', '2026-10-24T12:00:00Z');
  // Both dates are outside the one-week window.
  const stale = article('stale', '2026-10-16T12:00:00Z', '2026-10-16T12:00:00Z');

  const matches = matchIntelligence(
    [recentlyPublished, recentlyModified, stale],
    [asset],
    [],
    [],
    {},
    {},
    ONE_WEEK,
    NOW,
  );

  assert.deepEqual(
    matches
      .map((match) => match.articleIds)
      .flat()
      .sort(),
    ['recent-modified', 'recent-published'],
  );
});

test('vendor + product news matching is unfiltered when no scope is supplied', () => {
  const stale = article('stale', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z');
  assert.equal(matchIntelligence([stale], [asset], []).length, 1);
});

test('vendor + product news matching accepts an explicit zero-hour scope as unfiltered', () => {
  const stale = article('stale', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z');
  assert.equal(matchIntelligence([stale], [asset], [], [], {}, {}, 0, NOW).length, 1);
});

const daysAgo = (days: number) => new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

function fallbackCve(published: string, modified: string): NormalizedCVE {
  return {
    ...structuredClone(INITIAL_NORMALIZED_CVES[0]),
    cveId: 'CVE-2026-4242',
    title: 'Acme Widget vulnerability',
    description: 'A vulnerability affects the Acme Widget product.',
    publishedDate: published,
    modifiedDate: modified,
    cpeMatches: [],
    cpeMatchDetails: undefined,
    purls: [],
    versionRange: undefined,
    applicabilityRequiresReview: false,
  };
}

test('vendor + product fallback findings respect published and modified dates', () => {
  const fallbackAsset: WatchListItem = {
    ...structuredClone(INITIAL_WATCHLIST[0]),
    id: 'asset-fallback',
    vendor: 'acme',
    product: 'widget',
    version: '2.0',
    cpes: [],
    purls: [],
    active: true,
  };
  const settings = { ...structuredClone(INITIAL_SETTINGS), scopeHours: 168, autoDispatchEnabled: false };
  const run = (cve: NormalizedCVE) =>
    runVulnerabilityPipeline(INITIAL_FEEDS, [cve], [fallbackAsset], [], [], settings, 'test');

  // Both dates inside the window.
  const recent = run(fallbackCve(daysAgo(1), daysAgo(1)));
  assert.equal(recent.newFindings.length, 1);
  assert.equal(recent.newFindings[0].matchingMethod, 'VENDOR_PRODUCT_FALLBACK');

  // Published ten days ago but modified yesterday: the latest activity is in scope.
  assert.equal(run(fallbackCve(daysAgo(10), daysAgo(1))).newFindings.length, 1);

  // Both dates outside the window.
  assert.equal(run(fallbackCve(daysAgo(10), daysAgo(10))).newFindings.length, 0);
});
